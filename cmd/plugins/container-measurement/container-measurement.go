package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"strings"

	"cloud.google.com/go/compute/metadata"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/rest"
	"github.com/google/go-tpm/legacy/tpm2"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

const projectId = "tt-pns-pilab-cc"
const region = "us-west2"
const attestationServiceAddress = "https://confidentialcomputing.googleapis.com"

var (
	logger    *logrus.Logger
	verbose   bool
	mdsClient *metadata.Client
)

// our injector plugin
type plugin struct {
	stub stub.Stub
}

// demo struct in the Canonical Eventlog, a better choice is to refactor the Eventlog struct
type ContainerInfo struct {
	namespace   string
	podId       string
	containerId string
	originData  []byte
}

func (p *plugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, container *api.Container) (*api.Container, error) {
	logger.Infof("Logger from plugin CreateContainer")
	return container, nil
}

// Construct a container name for log messages.
func containerName(pod *api.PodSandbox, container *api.Container) string {
	if pod != nil {
		return pod.Namespace + "/" + pod.Name + "/" + container.Name
	}
	return container.Name
}

func (p *plugin) PostCreateContainer(ctx context.Context, pod *api.PodSandbox, container *api.Container) error {
	name := containerName(pod, container)
	logger.Infof("Container %s has been created", name)
	containerId := container.Id
	containerdClient := ctx.Value("containerd").(*containerd.Client)
	tpm := ctx.Value("tpm").(io.ReadWriteCloser)
	c, err := containerdClient.LoadContainer(ctx, containerId)
	if err != nil {
		logger.Errorf("Failed to load container: %+v", err)
		return err
	}
	image, err := c.Image(ctx)
	if err != nil {
		logger.Errorf("Failed to get image: %+v", err)
		return err
	}
	imageConfig, err := getImageConfig(ctx, image)
	if err != nil {
		logger.Errorf("Failed to get image config: %+v", err)
	}

	logger.Infof("Operator Input Image Ref   : %v\n", image.Name())
	logger.Infof("Image Digest               : %v\n", image.Target().Digest)

	logger.Infof("Exposed Ports:             : %v\n", imageConfig.ExposedPorts)
	logger.Infof("Image Labels               : %v\n", imageConfig.Labels)

	if imageConfigDescriptor, err := image.Config(ctx); err != nil {
		logger.Errorf("Failed to get image config %+v ", err)
	} else {
		logger.Infof("Image ID                   : %v\n", imageConfigDescriptor.Digest)
		logger.Infof("Image Annotations          : %v\n", imageConfigDescriptor.Annotations)
	}

	verifyClient, err := NewRESTClient(ctx, attestationServiceAddress, projectId, region)
	if err != nil {
		logger.Errorf("Failed to create REST client: %+v", err)
	}

	mdsClient = metadata.NewClient(nil)
	token, err := RetrieveAuthToken(mdsClient)
	if err != nil {
		logger.Errorf("Failed to retrieve auth token: %+v", err)
		return err
	}
	// Create a new signaturediscovery client to fetch signatures.
	sdClient := getSignatureDiscoveryClient(containerdClient, token, image.Target())
	principalFetcherWithImpersonate := func(audience string) ([][]byte, error) {
		tokens, err := PrincipalFetcher(audience, mdsClient)
		if err != nil {
			return nil, err
		}

		// Fetch impersonated ID tokens.
		//for _, sa := range launchSpec.ImpersonateServiceAccounts {
		//	idToken, err := FetchImpersonatedToken(ctx, sa, audience)
		//	if err != nil {
		//		return nil, fmt.Errorf("failed to get impersonated token for %v: %w", sa, err)
		//	}
		//
		//	tokens = append(tokens, idToken)
		//}
		return tokens, nil
	}

	attestAgent, err := CreateAttestationAgent(tpm, client.GceAttestationKeyECC, verifyClient, sdClient, principalFetcherWithImpersonate, logger)
	if err != nil {
		logger.Errorf("Failed to create attestation agent: %+v", err)
		return err
	}
	containerSpec, err := c.Spec(ctx)
	if err != nil {
		logger.Errorf("Failed to get container spec: %+v", err)
	}
	if err := measureCELEvents(ctx, attestAgent, image, pod.Namespace, pod.Id, containerId, containerSpec.Process.Args, containerSpec.Process.Env); err != nil {
		logger.Errorf("Failed to measure container CEL events: %+v", err)
	}

	defer attestAgent.Close()

	return nil
}

func main() {
	var (
		pluginName string
		pluginIdx  string
		opts       []stub.Option
		err        error
	)

	containerdClient, err := containerd.New(DefaultAddress)
	if err != nil {
		log.Fatalf("Failed to connect to containerd: %+v ", err)
	}
	defer containerdClient.Close()

	tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		log.Fatalf("Failed to open the tpm: %+v ", err)
	}
	defer tpm.Close()

	gceAk, err := client.GceAttestationKeyECC(tpm)
	if err != nil {
		log.Fatalf("Failed to get GCE attestation key: %+v ", err)
	}
	defer gceAk.Close()

	ctx := context.Background()
	context.WithValue(ctx, "containerd", containerdClient)

	context.WithValue(ctx, "tpm", tpm)

	logger = logrus.StandardLogger()
	logger.SetFormatter(&logrus.TextFormatter{
		PadLevelText: true,
	})

	flag.StringVar(&pluginName, "name", "", "plugin name to register to NRI")
	flag.StringVar(&pluginIdx, "idx", "", "plugin index to register to NRI")
	flag.BoolVar(&verbose, "verbose", false, "enable (more) verbose logging")
	flag.Parse()

	if pluginName != "" {
		opts = append(opts, stub.WithPluginName(pluginName))
	}
	if pluginIdx != "" {
		opts = append(opts, stub.WithPluginIdx(pluginIdx))
	}

	p := &plugin{}

	err = p.stub.Run(ctx)
	if err != nil {
		log.Fatalf("plugin exited with error %v", err)
	}
}

func getImageConfig(ctx context.Context, image containerd.Image) (v1.ImageConfig, error) {
	ic, err := image.Config(ctx)
	if err != nil {
		return v1.ImageConfig{}, err
	}
	switch ic.MediaType {
	case v1.MediaTypeImageConfig, images.MediaTypeDockerSchema2Config:
		p, err := content.ReadBlob(ctx, image.ContentStore(), ic)
		if err != nil {
			return v1.ImageConfig{}, err
		}
		var ociimage v1.Image
		if err := json.Unmarshal(p, &ociimage); err != nil {
			return v1.ImageConfig{}, err
		}
		return ociimage.Config, nil
	}
	return v1.ImageConfig{}, fmt.Errorf("unknown image config media type %s", ic.MediaType)
}

func measureCELEvents(ctx context.Context, agent AttestationAgent, image containerd.Image, namespace string, podId string, containerId string, args []string, envs []string) error {
	if err := measureContainerClaims(ctx, agent, image, namespace, podId, containerId, args, envs); err != nil {
		return err
	}

	separator := cel.CosTlv{
		EventType:    cel.LaunchSeparatorType,
		EventContent: nil, // Success
	}
	return agent.MeasureEvent(separator)
}

func measureContainerClaims(ctx context.Context, agent AttestationAgent, image containerd.Image, namespace string, podId string, containerId string, args []string, envs []string) error {
	containerInfo := &ContainerInfo{
		namespace:   namespace,
		podId:       podId,
		containerId: containerId,
		originData:  []byte(image.Name()),
	}
	imageRefData, err := json.Marshal(containerInfo)
	if err != nil {
		logger.Errorf("Failed to marshal container info: %+v ", err)
		return err
	}

	if err := agent.MeasureEvent(cel.CosTlv{EventType: cel.ImageRefType, EventContent: imageRefData}); err != nil {
		return err
	}

	containerInfo.originData = []byte(image.Target().Digest)
	imageDigestData, err := json.Marshal(containerInfo)
	if err != nil {
		logger.Errorf("Failed to marshal container info: %+v ", err)
		return err
	}
	if err := agent.MeasureEvent(cel.CosTlv{EventType: cel.ImageDigestType, EventContent: imageDigestData}); err != nil {
		return err
	}

	for _, arg := range args {
		containerInfo.originData = []byte(arg)
		argData, err := json.Marshal(containerInfo)
		if err != nil {
			return nil
		}
		if err := agent.MeasureEvent(cel.CosTlv{EventType: cel.ArgType, EventContent: argData}); err != nil {
			return err
		}
	}

	for _, env := range envs {
		containerInfo.originData = []byte(env)
		argData, err := json.Marshal(containerInfo)
		if err != nil {
			return nil
		}
		if err := agent.MeasureEvent(cel.CosTlv{EventType: cel.EnvVarType, EventContent: argData}); err != nil {
			return err
		}
	}

	return nil
}

// NewRESTClient returns a REST verifier.Client that points to the given address.
// It defaults to the Attestation Verifier instance at
// https://confidentialcomputing.googleapis.com.
func NewRESTClient(ctx context.Context, asAddr string, ProjectID string, Region string) (verifier.Client, error) {
	httpClient, err := google.DefaultClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %v", err)
	}

	opts := []option.ClientOption{option.WithHTTPClient(httpClient)}
	if asAddr != "" {
		opts = append(opts, option.WithEndpoint(asAddr))
	}

	restClient, err := rest.NewClient(ctx, ProjectID, Region, opts...)
	if err != nil {
		return nil, err
	}
	return restClient, nil
}

// PrincipalFetcher fetch ID token with specific audience from Metadata server.
// See https://cloud.google.com/functions/docs/securing/authenticating#functions-bearer-token-example-go.
func PrincipalFetcher(audience string, mdsClient *metadata.Client) ([][]byte, error) {
	u := url.URL{
		Path: "instance/service-accounts/default/identity",
		RawQuery: url.Values{
			"audience": {audience},
			"format":   {"full"},
		}.Encode(),
	}
	idToken, err := mdsClient.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get principal tokens: %w", err)
	}

	tokens := [][]byte{[]byte(idToken)}
	return tokens, nil
}

func getSignatureDiscoveryClient(cdClient *containerd.Client, token oauth2.Token, imageDesc v1.Descriptor) Fetcher {
	var remoteOpt containerd.RemoteOpt
	if token.Valid() {
		remoteOpt = containerd.WithResolver(Resolver(token.AccessToken))
	}
	return New(cdClient, imageDesc, remoteOpt)
}

// Resolver returns a custom resolver that can use the token to authenticate with
// the repo.
func Resolver(token string) remotes.Resolver {
	options := docker.ResolverOptions{}

	credentials := func(host string) (string, string, error) {
		// append the token if is talking to Artifact Registry or GCR Registry
		if strings.HasSuffix(host, "docker.pkg.dev") || strings.HasSuffix(host, "gcr.io") {
			return "_token", token, nil
		}
		return "", "", nil
	}
	authOpts := []docker.AuthorizerOpt{docker.WithAuthCreds(credentials)}
	options.Authorizer = docker.NewDockerAuthorizer(authOpts...)

	return docker.NewResolver(options)
}

// RetrieveAuthToken takes in a metadata server client, and uses it to read the
// default service account token from a GCE VM and returns the token.
func RetrieveAuthToken(client *metadata.Client) (oauth2.Token, error) {
	data, err := client.Get("instance/service-accounts/default/token")
	if err != nil {
		return oauth2.Token{}, err
	}

	var token oauth2.Token
	if err := json.Unmarshal([]byte(data), &token); err != nil {
		return oauth2.Token{}, err
	}

	return token, nil
}
