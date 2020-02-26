module sigs.k8s.io/external-dns

go 1.13

require (
	cloud.google.com/go v0.50.0
	github.com/Azure/azure-sdk-for-go v36.0.0+incompatible
	github.com/Azure/go-autorest/autorest v0.9.4
	github.com/Azure/go-autorest/autorest/adal v0.6.0
	github.com/Azure/go-autorest/autorest/azure/auth v0.0.0-00010101000000-000000000000
	github.com/Azure/go-autorest/autorest/to v0.3.0
	github.com/akamai/AkamaiOPEN-edgegrid-golang v0.9.5
	github.com/alecthomas/assert v0.0.0-20170929043011-405dbfeb8e38 // indirect
	github.com/alecthomas/colour v0.1.0 // indirect
	github.com/alecthomas/kingpin v2.2.5+incompatible
	github.com/alecthomas/repr v0.0.0-20181024024818-d37bc2a10ba1 // indirect
	github.com/alecthomas/units v0.0.0-20190924025748-f65c72e2690d // indirect
	github.com/aliyun/alibaba-cloud-sdk-go v0.0.0-20180828111155-cad214d7d71f
	github.com/aws/aws-sdk-go v1.27.4
	github.com/cloudflare/cloudflare-go v0.10.1
	github.com/cloudfoundry-community/go-cfclient v0.0.0-20190201205600-f136f9222381
	github.com/coreos/bbolt v1.3.3 // indirect
	github.com/coreos/etcd v3.3.15+incompatible
	github.com/denverdino/aliyungo v0.0.0-20180815121905-69560d9530f5
	github.com/digitalocean/godo v1.19.0
	github.com/dnaeon/go-vcr v1.0.1 // indirect
	github.com/dnsimple/dnsimple-go v0.14.0
	github.com/exoscale/egoscale v0.18.1
	github.com/fatih/color v1.9.0 // indirect
	github.com/ffledgling/pdns-go v0.0.0-20180219074714-524e7daccd99
	github.com/go-resty/resty v1.8.0 // indirect
	github.com/gobs/pretty v0.0.0-20180724170744-09732c25a95b // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/gophercloud/gophercloud v0.1.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.1.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.12.2 // indirect
	//github.com/heptio/contour v0.15.0
	github.com/infobloxopen/infoblox-go-client v0.0.0-20180606155407-61dc5f9b0a65
	github.com/linki/instrumented_http v0.2.0
	github.com/linode/linodego v0.3.0
	github.com/mdempsky/unconvert v0.0.0-20190921185256-3ecd357795af // indirect
	github.com/miekg/dns v1.0.14
	github.com/nesv/go-dynect v0.6.0
	github.com/nic-at/rc0go v1.1.0
	github.com/oracle/oci-go-sdk v1.8.0
	github.com/pkg/errors v0.9.1
	github.com/projectcontour/contour v1.1.0
	github.com/prometheus/client_golang v1.1.0
	github.com/sanyu/dynectsoap v0.0.0-20181203081243-b83de5edc4e0
	github.com/sergi/go-diff v1.1.0 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/smartystreets/go-aws-auth v0.0.0-20180515143844-0c1422d1fdb9 // indirect
	github.com/smartystreets/gunit v1.1.1 // indirect
	github.com/stretchr/testify v1.4.0
	github.com/tmc/grpc-websocket-proxy v0.0.0-20200122045848-3419fae592fc // indirect
	github.com/transip/gotransip v5.8.2+incompatible
	github.com/vinyldns/go-vinyldns v0.0.0-20190611170422-7119fe55ed92
	go.uber.org/zap v1.13.0 // indirect
	golang.org/x/net v0.0.0-20200114155413-6afb5195e5aa
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/sys v0.0.0-20200124204421-9fbb57f87de9 // indirect
	golang.org/x/tools v0.0.0-20200131211209-ecb101ed6550 // indirect
	google.golang.org/api v0.15.0
	gopkg.in/ns1/ns1-go.v2 v2.0.0-20190322154155-0dafb5275fd1
	gopkg.in/yaml.v2 v2.2.8
	gopkg.in/yaml.v3 v3.0.0-20200121175148-a6ecf24a6d71 // indirect
	istio.io/api v0.0.0-20200131231258-082bb2339152
	istio.io/client-go v0.0.0-20200131232717-5ffce782149e
	istio.io/istio v0.0.0-20200131213054-ff72755abaac
	//istio.io/api v1.4.0 //v0.0.0-20190820204432-483f2547d882
	//istio.io/istio v1.4.0 //v0.0.0-20190322063008-2b1331886076
	k8s.io/api v0.17.2
	k8s.io/apimachinery v0.17.2
	k8s.io/client-go v0.17.2 //+incompatible
	k8s.io/gengo v0.0.0-20200127102705-1e9b17e831be // indirect
	k8s.io/kube-openapi v0.0.0-20200130172213-cdac1c71ff9f // indirect
	mvdan.cc/unparam v0.0.0-20191111180625-960b1ec0f2c2 // indirect
	sigs.k8s.io/controller-tools v0.2.5 // indirect
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.0.1+incompatible
	github.com/Azure/go-autorest/autorest => github.com/Azure/go-autorest/autorest v0.9.1
	github.com/Azure/go-autorest/autorest/adal => github.com/Azure/go-autorest/autorest/adal v0.6.0
	github.com/Azure/go-autorest/autorest/azure/auth => github.com/Azure/go-autorest/autorest/azure/auth v0.3.0
	github.com/golang/glog => github.com/kubermatic/glog-logrus v0.0.0-20180829085450-3fa5b9870d1d
	github.com/h2non/gock => gopkg.in/h2non/gock.v1 v1.0.14
	//istio.io/api => istio.io/api v0.0.0-20190820204432-483f2547d882
	//istio.io/istio => istio.io/istio v0.0.0-20190911205955-c2bd59595ce6
	//k8s.io/api => k8s.io/api v0.0.0-20190817221950-ebce17126a01
	//k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20190919022157-e8460a76b3ad
	//k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190817221809-bf4de9df677c
	//k8s.io/cli-runtime => k8s.io/cli-runtime v0.0.0-20190817224438-0337ccdab819
	//k8s.io/client-go => k8s.io/client-go v0.0.0-20190817222206-ee6c071a42cf
	//k8s.io/code-generator => k8s.io/code-generator v0.0.0-20181117043124-c2090bec4d9b
	k8s.io/klog => github.com/mikkeloscar/knolog v0.0.0-20190326191552-80742771eb6b
)
