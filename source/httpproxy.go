package source

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"
	"text/template"

	contour "github.com/projectcontour/contour/apis/generated/clientset/versioned"
	contourapi "github.com/projectcontour/contour/apis/projectcontour/v1"
	contourinformers "github.com/projectcontour/contour/apis/generated/informers/externalversions"
	extinformers "github.com/projectcontour/contour/apis/generated/informers/externalversions/projectcontour/v1"
	"github.com/pkg/errors"	
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"sigs.k8s.io/external-dns/endpoint"
)

type httpProxySource struct {
	kubeClient       kubernetes.Interface
	contourClient    contour.Interface
	contourLoadBalancerService string
	namespace        string
	annotationFilter string
	fqdnTemplate               *template.Template
	combineFQDNAnnotation      bool
	ignoreHostnameAnnotation bool
	checkHTTPProxyHealth bool
	httpProxyInformer extinformers.HTTPProxyInformer
}

func NewContourHTTPProxySource(
	kubeClient kubernetes.Interface,
	contourClient contour.Interface,
	contourLoadBalancerService string,
	namespace string,
	annotationFilter string,
	fqdnTemplate string,
	combineFqdnAnnotation bool,
	ignoreHostnameAnnotation bool,
	checkHTTPProxyHealth bool,
) (Source, error) {
	var (
		tmpl *template.Template
		err error
	)
	if fqdnTemplate != "" {
		tmpl, err = template.New("endpoint").Funcs(template.FuncMap{
			"trimPrefix": strings.TrimPrefix,
		}).Parse(fqdnTemplate)
		if err != nil {
			return nil, err
		}
	}

	if _, _, err = parseContourLoadBalancerService(contourLoadBalancerService); err != nil {
		return nil, err
	}

	// Use shared informer to listen for add/update/delete of httpProxies in the specified namespace.
	// Set resync period to 0, to prevent processing when nothing has changed.
	informerFactory := contourinformers.NewSharedInformerFactoryWithOptions(
		contourClient,
		0,
		contourinformers.WithNamespace(namespace),
	)
	httpProxyInformer := informerFactory.Projectcontour().V1().HTTPProxies()

	// Add default resource event handlers to properly initialize informer.
	httpProxyInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {	
			},
		},
	)

	// TODO informer is not explicitly stopped since controller is not passing in its channel.
	informerFactory.Start(wait.NeverStop)

	// wait for the local cache to be populated.
	err = wait.Poll(time.Second, 60*time.Second, func() (bool, error) {
		return httpProxyInformer.Informer().HasSynced() == true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sync cache: %v", err)
	}

	fmt.Printf("creating httpproxy source with namespace %s \n", namespace)
	return &httpProxySource{
		kubeClient:                 kubeClient,
		contourClient:              contourClient,
		contourLoadBalancerService: contourLoadBalancerService,
		namespace:                  namespace,
		annotationFilter:           annotationFilter,
		fqdnTemplate:               tmpl,
		combineFQDNAnnotation:      combineFqdnAnnotation,
		ignoreHostnameAnnotation:   ignoreHostnameAnnotation,
		httpProxyInformer:       httpProxyInformer,
	}, nil
}

func (sc *httpProxySource) Endpoints() ([]*endpoint.Endpoint, error) {
	hps, err := sc.httpProxyInformer.Lister().HTTPProxies(sc.namespace).List(labels.Everything())
	if err != nil {
		return nil, err
	}

	hps, err = sc.filterByAnnotations(hps)
	if err != nil {
		return nil, err
	}

	endpoints := []*endpoint.Endpoint{}

	for _, hp := range hps {
		// Check controller annotation to see if we are responsible.
		controller, ok := hp.Annotations[controllerAnnotationKey]
		if ok && controller != controllerAnnotationValue {
			log.Debugf("Skipping httpproxy %s/%s because controller value does not match, found: %s, requhped: %s",
				hp.Namespace, hp.Name, controller, controllerAnnotationValue)
			continue
		} else if hp.Status.CurrentStatus != "valid" {
			log.Debugf("Skipping httpproxy %s/%s because it is not valid", hp.Namespace, hp.Name)
			continue
		}

		hpEndpoints, err := sc.endpointsFromHttpProxy(hp)
		if err != nil {
			return nil, err
		}

		// apply template if fqdn is missing on httpproxy
		if (sc.combineFQDNAnnotation || len(hpEndpoints) == 0) && sc.fqdnTemplate != nil {
			tmplEndpoints, err := sc.endpointsFromTemplate(hp)
			if err != nil {
				return nil, err
			}

			if sc.combineFQDNAnnotation {
				hpEndpoints = append(hpEndpoints, tmplEndpoints...)
			} else {
				hpEndpoints = tmplEndpoints
			}
		}

		if len(hpEndpoints) == 0 {
			log.Debugf("No endpoints could be generated from httpproxy %s/%s", hp.Namespace, hp.Name)
			continue
		}

		log.Debugf("Endpoints generated from httpproxy: %s/%s: %v", hp.Namespace, hp.Name, hpEndpoints)
		sc.setResourceLabel(hp, hpEndpoints)
		endpoints = append(endpoints, hpEndpoints...)
	}

	for _, ep := range endpoints {
		sort.Sort(ep.Targets)
	}

	return endpoints, nil

}

func (sc *httpProxySource) endpointsFromTemplate(hp *contourapi.HTTPProxy) ([]*endpoint.Endpoint, error) {
	// Process the whole template string
	var buf bytes.Buffer
	err := sc.fqdnTemplate.Execute(&buf, hp)
	if err != nil {
		return nil, fmt.Errorf("failed to apply template on HTTPProxy %s/%s: %v", hp.Namespace, hp.Name, err)
	}

	hostnames := buf.String()

	ttl, err := getTTLFromAnnotations(hp.Annotations)
	if err != nil {
		log.Warn(err)
	}

	targets := getTargetsFromTargetAnnotation(hp.Annotations)

	if len(targets) == 0 {
		targets, err = sc.targetsFromContourLoadBalancer()
		if err != nil {
			return nil, err
		}
	}

	providerSpecific, setIdentifier := getProviderSpecificAnnotations(hp.Annotations)

	var endpoints []*endpoint.Endpoint
	// splits the FQDN template and removes the trailing periods
	hostnameList := strings.Split(strings.Replace(hostnames, " ", "", -1), ",")
	for _, hostname := range hostnameList {
		hostname = strings.TrimSuffix(hostname, ".")
		endpoints = append(endpoints, endpointsForHostname(hostname, targets, ttl, providerSpecific, setIdentifier)...)
	}
	return endpoints, nil
}

// filterByAnnotations filters a list of configs by a given annotation selector.
func (sc *httpProxySource) filterByAnnotations(httpProxies []*contourapi.HTTPProxy) ([]*contourapi.HTTPProxy, error) {
	labelSelector, err := metav1.ParseToLabelSelector(sc.annotationFilter)
	if err != nil {
		return nil, err
	}
	selector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		return nil, err
	}

	// empty filter returns original list
	if selector.Empty() {
		return httpProxies, nil
	}

	filteredList := []*contourapi.HTTPProxy{}

	for _, hp := range httpProxies {
		// convert the HTTPProxy's annotations to an equivalent label selector
		annotations := labels.Set(hp.Annotations)

		// include HTTPProxy if its annotations match the selector
		if selector.Matches(annotations) {
			filteredList = append(filteredList, hp)
		}
	}

	return filteredList, nil
}

func (sc *httpProxySource) endpointsFromHttpProxy(hp *contourapi.HTTPProxy) ([]*endpoint.Endpoint, error) {
	if hp.Status.CurrentStatus != "valid" {
		log.Warn(errors.Errorf("cannot generate endpoints for httpproxy with status %s", hp.Status.CurrentStatus))
		return nil, nil
	}
	
	var endpoints []*endpoint.Endpoint

	ttl, err := getTTLFromAnnotations(hp.Annotations)
	if err != nil {
		log.Warn(err)
	}

	targets := getTargetsFromTargetAnnotation(hp.Annotations)

	if len(targets) == 0 {
		targets, err = sc.targetsFromContourLoadBalancer()
		if err != nil {
			return nil, err
		}
	}

	providerSpecific, setIdentifier := getProviderSpecificAnnotations(hp.Annotations)

	if virtualHost := hp.Spec.VirtualHost; virtualHost != nil {
		if fqdn := virtualHost.Fqdn; fqdn != "" {
			endpoints = append(endpoints, endpointsForHostname(fqdn, targets, ttl, providerSpecific, setIdentifier)...)
		}
	}

	// Skip endpoints if we do not want entries from annotations
	if !sc.ignoreHostnameAnnotation {
		hostnameList := getHostnamesFromAnnotations(hp.Annotations)
		for _, hostname := range hostnameList {
			endpoints = append(endpoints, endpointsForHostname(hostname, targets, ttl, providerSpecific, setIdentifier)...)
		}
	}

	return endpoints, nil
}

func (sc *httpProxySource) setResourceLabel(hp *contourapi.HTTPProxy, endpoints []*endpoint.Endpoint) {
	for _, ep := range endpoints {
		ep.Labels[endpoint.ResourceLabelKey] = fmt.Sprintf("hp/%s/%s", hp.Namespace, hp.Name)
	}
}

func (sc *httpProxySource) targetsFromContourLoadBalancer() (targets endpoint.Targets, err error) {
	lbNamespace, lbName, err := parseContourLoadBalancerService(sc.contourLoadBalancerService)
	if err != nil {
		return nil, err
	}
	if svc, err := sc.kubeClient.CoreV1().Services(lbNamespace).Get(lbName, metav1.GetOptions{}); err != nil {
		log.Warn(err)
	} else {
		for _, lb := range svc.Status.LoadBalancer.Ingress {
			if lb.IP != "" {
				targets = append(targets, lb.IP)
			}
			if lb.Hostname != "" {
				targets = append(targets, lb.Hostname)
			}
		}
	}

	return
}