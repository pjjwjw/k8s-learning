- [1. 注册资源](#1-注册资源)
- [2. cobra参数解析](#2-cobra参数解析)
- [3. 创建apiserver通用配置](#3-创建apiserver通用配置)
	- [3.1. genericConfig实例化](#31-genericconfig实例化)
	- [3.2. openapi/swagger配置](#32-openapiswagger配置)
	- [3.3. etcd配置](#33-etcd配置)
	- [3.4. 认证配置](#34-认证配置)
	- [3.5. 授权配置](#35-授权配置)
	- [3.6. 准入控制器配置](#36-准入控制器配置)
- [4. 创建APIServer](#4-创建apiserver)
	- [4.1. 创建GenericAPIServer](#41-创建genericapiserver)
	- [4.2. 创建APIExtersionServer](#42-创建apiextersionserver)
	- [4.3. 创建KubeAPIServer](#43-创建kubeapiserver)
	- [4.4. 创建AggregatorServer](#44-创建aggregatorserver)
- [5. 启动https服务](#5-启动https服务)

# 1. 注册资源

apiserver启动的第一步是注册资源

apiserver通过go语言的import init机制资源注册至scheme

每个内置的资源都有一个install包, 导入这个包就可以把资源注册到scheme中

scheme中包含了两个map, 实现了资源的struct reflect.type到gvk的双向映射

有三种scheme， 内置资源(pod / service)注册至legacyscheme，聚合资源(metrice service)资源注册至aggregatorscheme, 拓展资源(crd / crdList)注册至extensionscheme.

注册流程:

[k8s.io/kubernetes/cmd/kube-apiserver/app](https://github.com/pjjwjw/kubernetes/blob/master/cmd/kube-apiserver/apiserver.go#L28) -> // import app package

regist to legacyscheme

["k8s.io/kubernetes/pkg/controlplane"](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L73)	-> // import controlplane package

["k8s.io/kubernetes/pkg/apis/xxx/install"](https://github.com/pjjwjw/kubernetes/blob/c7911a384cbc11a4b5003da081b181d6b814d07e/pkg/controlplane/import_known_versions.go#L21) // import install package

regist to extensionscheme

[extensionsapiserver "k8s.io/apiextensions-apiserver/pkg/apiserver"](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L35)

regist to aggregatorscheme

[aggregatorscheme "k8s.io/kube-aggregator/pkg/apiserver/scheme"](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L67)

# 2. cobra参数解析
[s := options.NewServerRunOptions()](https://github.com/pjjwjw/kubernetes/blob/master/cmd/kube-apiserver/app/server.go#L100)  // 初始化各个模块的参数配置

[completedOptions, err := Complete(s)](https://github.com/pjjwjw/kubernetes/blob/master/cmd/kube-apiserver/app/server.go#L132)  // 填充默认配置参数

[errs := completedOptions.Validate()](https://github.com/pjjwjw/kubernetes/blob/master/cmd/kube-apiserver/app/server.go#L138)  // 校验参数的合法性

[Run(completedOptions, genericapiserver.SetupSignalHandler())](https://github.com/pjjwjw/kubernetes/blob/master/cmd/kube-apiserver/app/server.go#L142)  // 将参数传给Run函数

# 3. 创建apiserver通用配置
## 3.1. genericConfig实例化
[command := app.NewAPIServerCommand()](https://github.com/pjjwjw/kubernetes/blob/master/cmd/kube-apiserver/apiserver.go#L32) -> 

[Run(completedOptions, genericapiserver.SetupSignalHandler())](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L142) ->

[server, err := CreateServerChain(completeOptions, stopCh)](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L174) ->

[kubeAPIServerConfig, serviceResolver, pluginInitializer, err := CreateKubeAPIServerConfig(completedOptions)](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L189) ->

[enericConfig, versionedInformers, serviceResolver, pluginInitializers, admissionPostStartHook, storageFactory, err := buildGenericConfig(s.ServerRunOptions, proxyTransport)](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L257) -> // 这个函数比较重要, 后面的认证 / 授权 / 准入控制的配置都在这个函数里面完成的

[genericConfig = genericapiserver.NewConfig(legacyscheme.Codecs)](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L376)  // 实例化genericConfig

[genericConfig.MergedResourceConfig = controlplane.DefaultAPIResourceConfigSource()](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L377)  // 设置启用的资源, 默认启用v1 beta, 不启用alpha

## 3.2. openapi/swagger配置
genericConfig.OpenAPIConfig用于生成OpenAPI规范, generatedopenapi.GetOpenAPIDefinitions由openapi-gen自动生成

[getOpenAPIDefinitions := openapi.GetOpenAPIDefinitionsWithoutDisabledFeatures(generatedopenapi.GetOpenAPIDefinitions)<br>genericConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(getOpenAPIDefinitions, openapinamer.NewDefinitionNamer(legacyscheme.Scheme, extensionsapiserver.Scheme, aggregatorscheme.Scheme))](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L400)


## 3.3. etcd配置
storageFactoryConfig定义了与apiserver与etcd交互的方式:

[storageFactoryConfig := kubeapiserver.NewStorageFactoryConfig()](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L412)

## 3.4. 认证配置
认证的作用是证明客户端的身份

apiserver提供了9种认证器, 分别是ClientCA / TokenAuth / ServiceAccountAuth ...

根据配置信息决定启用哪种认证器, 并将认证器加入认证器列表, 最后将证器列表包装起来并返回

请求到达apiserver时会遍历认证器列表, 只要有一个认证通过, 则通过.

[if lastErr = s.Authentication.ApplyTo(&genericConfig.Authentication, genericConfig.SecureServing, genericConfig.EgressSelector, genericConfig.OpenAPIConfig, clientgoExternalClient, versionedInformers); lastErr != nil {
		return
}](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L451) ->

[authInfo.Authenticator, openAPIConfig.SecurityDefinitions, err = authenticatorConfig.New()](https://github.com/pjjwjw/kubernetes/blob/ef2be5586eb2cc80fe619da81daa994dec9bf49e/pkg/kubeapiserver/options/authentication.go#L506) ->

[authenticator := union.New(authenticators...)<br>authenticator = group.NewAuthenticatedGroupAdder(authenticator)](https://github.com/pjjwjw/kubernetes/blob/34b0fcef5fc47e3fcddf7f6ca1b3e6176b2a5323/pkg/kubeapiserver/authenticator/config.go#L213)  // 包装认证器列表

[处理认证请求](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/authentication/request/union/union.go#L53)

``` golang
func (authHandler *unionAuthRequestHandler) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	var errlist []error
	for _, currAuthRequestHandler := range authHandler.Handlers {
		resp, ok, err := currAuthRequestHandler.AuthenticateRequest(req)
		if err != nil {
			if authHandler.FailOnError {
				return resp, ok, err
			}
			errlist = append(errlist, err)
			continue
		}

		if ok {
			return resp, ok, err
		}
	}

	return nil, false, utilerrors.NewAggregate(errlist)
}
```

## 3.5. 授权配置
授权的目的是判断某个用户是否对某种资源有某种操作权限

目前有6种授权机制: AllowAllow AllowDeny Webhook Node ABAC RBAC

依次遍历, 只要有一种通过则通过

// authorizers存放启用的授权器列表, ruleResolvers存放启用的授权期列表的解析器

[genericConfig.Authorization.Authorizer, genericConfig.RuleResolver, err = BuildAuthorizer(s, genericConfig.EgressSelector, versionedInformers)
](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L455)

## 3.6. 准入控制器配置
在认证/授权后, 持久化之前, 拦截请求, 对请求进行修改/校验/拒绝

目前有31种准入控制器, 每种都实现了Register方法. 通过Register方法将{控制器名字:Factory}注册至plugins中

[s := options.NewServerRunOptions()](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L100)

[Admission: kubeoptions.NewAdmissionOptions()](https://github.com/pjjwjw/kubernetes/blob/79550ed40c67a70534c1cb697e1fb7e7dbf96335/cmd/kube-apiserver/app/options/options.go#L106)

[RegisterAllAdmissionPlugins(options.Plugins)](https://github.com/pjjwjw/kubernetes/blob/4a24a08f936a295bf332b9567bea182e2feff554/pkg/kubeapiserver/options/admission.go#L55)

[func RegisterAllAdmissionPlugins(plugins *admission.Plugins)](https://github.com/pjjwjw/kubernetes/blob/b5ef684d90e2d6aacdd48094b858a8629041e97a/pkg/kubeapiserver/options/plugins.go#L109)

``` golang
func RegisterAllAdmissionPlugins(plugins *admission.Plugins) {
	alwayspullimages.Register(plugins)
	antiaffinity.Register(plugins)
	defaulttolerationseconds.Register(plugins)
	...
}

// Factory is a function that returns an Interface for admission decisions.
// The config parameter provides an io.Reader handler to the factory in
// order to load specific configurations. If no configuration is provided
// the parameter is nil.
type Factory func(config io.Reader) (Interface, error)

type Plugins struct {
	lock     sync.Mutex
	registry map[string]Factory
}

// Interface is an abstract, pluggable interface for Admission Control decisions.
type Interface interface {
	// Handles returns true if this admission controller can handle the given operation
	// where operation can be one of CREATE, UPDATE, DELETE, or CONNECT
	Handles(operation Operation) bool
}

// Operation is the type of resource operation being checked for admission control
type Operation string
```

# 4. 创建APIServer
创建APIServer的过程简单来说就是创建webservice, 给每个资源创建一个route, 并绑定handlers方法, handlers方法能够操作etcd. 然后将route添加到webservice中, 把webservice添加到container中. 这样当http请求到来时, 通过认证/授权/准入控制后, 便可根据url来操作对应资源的etcd. 

创建APIServer的流程为:
1. 创建GenericAPIServer, 这里会生成一个[handler](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/server/genericapiserver.go#L93), 里面包含用装饰器装饰过的FullHandlerChain用于认证/授权/准入控制, 以及一个Director用于http请求.
2. 实例化APIGroup, 一个组对应着一个APIGroup, APIGroup包含着本组下所有资源, 以及资源对应的storage, storage能够以restful形式操作etcd.
3. 通过InstallAPIGroup将gvr对应的url和storage注册到handler中, 然后将route添加到webservice中, 把webservice添加到container中. 这样当http请求到来时, 便可根据url来操作对应资源的etcd.

k8s目前有三者APIServer, 分别管理着不同类型的资源

## 4.1. 创建GenericAPIServer
[genericServer, err := c.GenericConfig.New("apiextensions-apiserver", delegationTarget)](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiextensions-apiserver/pkg/apiserver/apiserver.go#L134)

创建container

[apiServerHandler := NewAPIServerHandler(name, c.Serializer, handlerChainBuilder, delegationTarget.UnprotectedHandler())](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/server/config.go#L582)

[func NewAPIServerHandler(name string, s runtime.NegotiatedSerializer, handlerChainBuilder HandlerChainBuilderFn, notFoundHandler http.Handler) *APIServerHandler](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/server/handler.go#L73)	// 创建container

``` golang
func NewAPIServerHandler(name string, s runtime.NegotiatedSerializer, handlerChainBuilder HandlerChainBuilderFn, notFoundHandler http.Handler) *APIServerHandler {
	nonGoRestfulMux := mux.NewPathRecorderMux(name)
	if notFoundHandler != nil {
		nonGoRestfulMux.NotFoundHandler(notFoundHandler)
	}

	gorestfulContainer := restful.NewContainer()
	gorestfulContainer.ServeMux = http.NewServeMux()
	gorestfulContainer.Router(restful.CurlyRouter{}) // e.g. for proxy/{kind}/{name}/{*}
	gorestfulContainer.RecoverHandler(func(panicReason interface{}, httpWriter http.ResponseWriter) {
		logStackOnRecover(s, panicReason, httpWriter)
	})
	gorestfulContainer.ServiceErrorHandler(func(serviceErr restful.ServiceError, request *restful.Request, response *restful.Response) {
		serviceErrorHandler(s, serviceErr, request, response)
	})

	director := director{
		name:               name,
		goRestfulContainer: gorestfulContainer,
		nonGoRestfulMux:    nonGoRestfulMux,
	}

	return &APIServerHandler{
		FullHandlerChain:   handlerChainBuilder(director),
		GoRestfulContainer: gorestfulContainer,
		NonGoRestfulMux:    nonGoRestfulMux,
		Director:           director,
	}
}
```

注册genericAPIServer的相关API

| 类型 | url | 作用 |
| - | - | - |
| routes.Index | /<br>/index.html | index索引 |
| routes.Profiling | /debug/pprof| 分析性能的可视化页面 |
| routes.MetricsWithReset | /metrics | metrics性能指标 |
| routes.Version | /version | k8s版本 |

[installAPI(s, c.Config)](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/server/config.go#L744)

[func installAPI(s *GenericAPIServer, c *Config)](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/server/config.go#L826)

``` golang
func installAPI(s *GenericAPIServer, c *Config) {
	if c.EnableIndex {
		routes.Index{}.Install(s.listedPathProvider, s.Handler.NonGoRestfulMux)	// 获取index索引
	}
	if c.EnableProfiling {
		routes.Profiling{}.Install(s.Handler.NonGoRestfulMux)	// 分析性能的可视化页面
		if c.EnableContentionProfiling {
			goruntime.SetBlockProfileRate(1)
		}
		// so far, only logging related endpoints are considered valid to add for these debug flags.
		routes.DebugFlags{}.Install(s.Handler.NonGoRestfulMux, "v", routes.StringFlagPutHandler(logs.GlogSetter))
	}
	if c.EnableMetrics {
		if c.EnableProfiling {
			routes.MetricsWithReset{}.Install(s.Handler.NonGoRestfulMux)	// 获取metrics指标信息
		} else {
			routes.DefaultMetrics{}.Install(s.Handler.NonGoRestfulMux)
		}
	}

	routes.Version{Version: c.Version}.Install(s.Handler.GoRestfulContainer)	// 获取k8s版本

	if c.EnableDiscovery {
		s.Handler.GoRestfulContainer.Add(s.DiscoveryGroupManager.WebService())
	}
	if c.FlowControl != nil && feature.DefaultFeatureGate.Enabled(features.APIPriorityAndFairness) {
		c.FlowControl.Install(s.Handler.NonGoRestfulMux)
	}
}
```
## 4.2. 创建APIExtersionServer
APIExtersionServer负责管理apiextension.k8s.io组下的所有资源, 创建流程如下为:
1. 创建GenericAPIServer
2. 实例化CustomResourceDefinitions, APIExtersionServer通过此对象进行管理
3. 实例化APIGroup, 一个组对应着一个APIGroup, APIGroup包含着本组下所有资源, 以及资源对应的storage, storage能够以restful形式操作etcd
4. 通过InstallAPIGroup将gvr对应的url和storage注册到APIExtersionServerHandler中, 进而添加到go-restful的route里.

[apiExtensionsServer, err := createAPIExtensionsServer(apiExtensionsConfig, genericapiserver.NewEmptyDelegateWithCustomHandler(notFoundHandler))](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L202)

[return apiextensionsConfig.Complete().New(delegateAPIServer)](https://github.com/pjjwjw/kubernetes/blob/d78f3cd47b91987f8a646fe0d2be7074f5f0efd1/cmd/kube-apiserver/app/apiextensions.go#L104)

[func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*CustomResourceDefinitions, error)](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiextensions-apiserver/pkg/apiserver/apiserver.go#L133)

``` golang
// New returns a new instance of CustomResourceDefinitions from the given config.
func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*CustomResourceDefinitions, error) {
	genericServer, err := c.GenericConfig.New("apiextensions-apiserver", delegationTarget) // 创建名为apiextensions-apiserver的genericServer 创建container 通过installAPI注册genericAPIServer的相关API

	s := &CustomResourceDefinitions{
		GenericAPIServer: genericServer,
	} // 创建CustomResourceDefinitions的对象, apiExtensionServer拓展服务通过该对象进行管理

	apiResourceConfig := c.GenericConfig.MergedResourceConfig
	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(apiextensions.GroupName, Scheme, metav1.ParameterCodec, Codecs) // apiGroupInfo的PrioritizedVersions存储了gv, VersionedResourcesStorageMap存储了vr->storage, storage与etcd交互, 负责对资源对象crud
	if apiResourceConfig.VersionEnabled(v1.SchemeGroupVersion) {
		storage := map[string]rest.Storage{}
		// customresourcedefinitions
		customResourceDefinitionStorage, err := customresourcedefinition.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter)
		if err != nil {
			return nil, err
		}
		storage["customresourcedefinitions"] = customResourceDefinitionStorage
		storage["customresourcedefinitions/status"] = customresourcedefinition.NewStatusREST(Scheme, customResourceDefinitionStorage)

		apiGroupInfo.VersionedResourcesStorageMap[v1.SchemeGroupVersion.Version] = storage
	}

	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil { // 将apigroup注册进GenericAPIServer
		return nil, err
	}
	...
}
```

[err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo)](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiextensions-apiserver/pkg/apiserver/apiserver.go#L165)	// apigroup注册

[return s.InstallAPIGroups(apiGroupInfo)](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/server/genericapiserver.go#L652)

[err := s.installAPIResources(APIGroupPrefix, apiGroupInfo, openAPIModels)](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/server/genericapiserver.go#L616)

[r, err := apiGroupVersion.InstallREST(s.Handler.GoRestfulContainer)](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/server/genericapiserver.go#L558)

[func (g *APIGroupVersion) InstallREST(container *restful.Container) ([]*storageversion.ResourceInfo, error)](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/endpoints/groupversion.go#L108) ->  // ws添加到container

``` golang
func (g *APIGroupVersion) InstallREST(container *restful.Container) ([]*storageversion.ResourceInfo, error) {
	prefix := path.Join(g.Root, g.GroupVersion.Group, g.GroupVersion.Version)	// prefix定义了url, 此处为/apis/apiextension.k8s.io/v1
	installer := &APIInstaller{	// 实例化APIInstall安装器
		group:             g,
		prefix:            prefix,
		minRequestTimeout: g.MinRequestTimeout,
	}

	apiResources, resourceInfos, ws, registrationErrors := installer.Install()	// 内部创建了一个webservice, 并通过a.registerResourceHandlers函数为资源注册对应的Handlers方法, 并为ws添加路由
	versionDiscoveryHandler := discovery.NewAPIVersionHandler(g.Serializer, g.GroupVersion, staticLister{apiResources})
	versionDiscoveryHandler.AddToWebService(ws)
	container.Add(ws)
	return removeNonPersistedResources(resourceInfos), utilerrors.NewAggregate(registrationErrors)
}
```

[apiResources, resourceInfos, ws, registrationErrors := installer.Install()](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/endpoints/groupversion.go#L116) ->

[apiResource, resourceInfo, err := a.registerResourceHandlers(path, a.group.Storage[path], ws)](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/endpoints/installer.go#L114) ->

[func (a *APIInstaller) registerResourceHandlers(path string, storage rest.Storage, ws *restful.WebService) (*metav1.APIResource, *storageversion.ResourceInfo, error)](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/endpoints/installer.go#L191)  // 注册路由

``` golang
route := ws.GET(action.Path).To(handler).
	Doc(doc).
	Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed.")).
	Operation("read"+namespaced+kind+strings.Title(subresource)+operationSuffix).
	Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
	Returns(http.StatusOK, "OK", producedObject).
	Writes(producedObject)
...
routes = append(routes, route)
...
for _, route := range routes {
	route.Metadata(ROUTE_META_GVK, metav1.GroupVersionKind{
		Group:   reqScope.Kind.Group,
		Version: reqScope.Kind.Version,
		Kind:    reqScope.Kind.Kind,
	})
	route.Metadata(ROUTE_META_ACTION, strings.ToLower(action.Verb))
	ws.Route(route)
}
```



## 4.3. 创建KubeAPIServer
将gvr与storage的映射关系存储至apigroup, 并通过安装为资源注册对应的handlers方法, 将handlers添加到ws, ws添加到container中

[err := m.InstallLegacyAPI(&c, c.GenericConfig.RESTOptionsGetter, legacyRESTStorageProvider)](https://github.com/pjjwjw/kubernetes/blob/d2abddd9096e30a6c47c72e3e43a033e99c1c149/pkg/controlplane/instance.go#L410)	// 注册无组名的资源, 例如http://localhost:8080/api/v1/pods

[err := m.InstallAPIs(c.ExtraConfig.APIResourceConfigSource, c.GenericConfig.RESTOptionsGetter, restStorageProviders...)](https://github.com/pjjwjw/kubernetes/blob/d2abddd9096e30a6c47c72e3e43a033e99c1c149/pkg/controlplane/instance.go#L444) // 注册有组名的资源, 例如http://localhost:8080/apis/apps/v1/deployments

## 4.4. 创建AggregatorServer
将gvr与storage的映射关系存储至apigroup, 并通过安装为资源注册对应的handlers方法, 将handlers添加到ws, ws添加到container中

# 5. 启动https服务
[prepared.Run(stopCh)](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L184) ->

[prepared, err := server.PrepareRun()](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L179) ->

[prepared := s.GenericAPIServer.PrepareRun()](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/kube-aggregator/pkg/apiserver/apiserver.go#L360) ->

[return preparedGenericAPIServer{s}](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/server/genericapiserver.go#L383)

[stoppedCh, listenerStoppedCh, err := s.NonBlockingRun(stopHttpServerCh, shutdownTimeout)](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/server/genericapiserver.go#L440) ->

[stoppedCh, listenerStoppedCh, err = s.SecureServingInfo.ServeWithListenerStopped(s.Handler, shutdownTimeout, internalStopCh)](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/server/genericapiserver.go#L503)

[func (s *SecureServingInfo) ServeWithListenerStopped(handler http.Handler, shutdownTimeout time.Duration, stopCh <-chan struct{}) (<-chan struct{}, <-chan struct{}, error)](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/server/secure_serving.go#L211)