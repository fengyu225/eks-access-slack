package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	accessv1alpha1 "eks-access-slack/controller/api/v1alpha1"
	"eks-access-slack/controller/pkg/controller"
	"eks-access-slack/slack-bot/pkg/handler"
	"eks-access-slack/slack-bot/pkg/k8sclient"
	"eks-access-slack/slack-bot/pkg/slackclient"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(accessv1alpha1.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var defaultRegion string
	var cleanupInterval string

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&defaultRegion, "default-region", "ap-northeast-2", "Default AWS region for EKS operations")
	flag.StringVar(&cleanupInterval, "cleanup-interval", "5m", "Interval for AWS cleanup worker")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	cleanupDuration, err := time.ParseDuration(cleanupInterval)
	if err != nil {
		setupLog.Error(err, "invalid cleanup interval, using default 5m")
		cleanupDuration = 5 * time.Minute
	}

	slackBotToken := os.Getenv("SLACK_BOT_TOKEN")
	slackAppToken := os.Getenv("SLACK_APP_TOKEN")
	k8sNamespace := os.Getenv("K8S_NAMESPACE")
	if k8sNamespace == "" {
		k8sNamespace = "default"
	}

	logrus.Info("Configuration:")
	logrus.Info("  K8S_NAMESPACE: ", k8sNamespace)
	logrus.Info("  DEFAULT_REGION: ", defaultRegion)
	logrus.Info("  CLEANUP_INTERVAL: ", cleanupDuration)
	logrus.Info("  SLACK_ENABLED: ", slackBotToken != "" && slackAppToken != "")

	notificationQueue := make(chan accessv1alpha1.NotificationEvent, 1000)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "eks-access-manager.eksaccess.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	eksAccessReconciler := &controller.EKSAccessRequestReconciler{
		Client:            mgr.GetClient(),
		Log:               ctrl.Log.WithName("controllers").WithName("EKSAccessRequest"),
		Scheme:            mgr.GetScheme(),
		Recorder:          mgr.GetEventRecorderFor("eksaccessrequest-controller"),
		DefaultRegion:     defaultRegion,
		NotificationQueue: notificationQueue,
	}

	if err = eksAccessReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "EKSAccessRequest")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eksAccessReconciler.StartCleanupWorker(ctx, cleanupDuration)
	setupLog.Info("Started AWS cleanup worker", "interval", cleanupDuration)

	if err = (&controller.ApprovalPolicyReconciler{
		Client:   mgr.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("ApprovalPolicy"),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("approvalpolicy-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ApprovalPolicy")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	if slackBotToken != "" && slackAppToken != "" {
		slackClient := slackclient.NewClient(slackBotToken)
		k8sClient, err := k8sclient.NewK8sClient(k8sNamespace)
		if err != nil {
			setupLog.Error(err, "Failed to create Kubernetes client for Slack")
			os.Exit(1)
		}

		slackHandler := handler.NewHandler(slackClient, k8sClient, notificationQueue)

		go func() {
			logrus.Info("Starting Slack notification consumer")
			slackHandler.ConsumeNotifications(ctx)
		}()

		// Setup Socket Mode client
		api := slack.New(
			slackBotToken,
			slack.OptionDebug(false),
			slack.OptionLog(log.New(os.Stdout, "slack-api: ", log.Lshortfile|log.LstdFlags)),
			slack.OptionAppLevelToken(slackAppToken),
		)

		socketClient := socketmode.New(
			api,
			socketmode.OptionDebug(false),
			socketmode.OptionLog(log.New(os.Stdout, "socketmode: ", log.Lshortfile|log.LstdFlags)),
		)

		go func() {
			for evt := range socketClient.Events {
				switch evt.Type {
				case socketmode.EventTypeConnecting:
					logrus.Info("Connecting to Slack with Socket Mode...")
				case socketmode.EventTypeConnectionError:
					logrus.Errorf("Connection failed: %v. Retrying later...", evt)
				case socketmode.EventTypeConnected:
					logrus.Info("Connected to Slack with Socket Mode.")
				case socketmode.EventTypeInteractive:
					slackHandler.HandleInteractive(&evt, socketClient)
				case socketmode.EventTypeSlashCommand:
					logrus.Info("Received slash command event")
					slackHandler.HandleSlashCommand(&evt, socketClient)
				case socketmode.EventTypeHello:
					logrus.Debug("Received hello event from Slack")
				case socketmode.EventTypeEventsAPI:
					if evt.Request != nil {
						socketClient.Ack(*evt.Request)
					}
				default:
					if evt.Request != nil {
						socketClient.Ack(*evt.Request)
					}
				}
			}
		}()

		go func() {
			logrus.Info("Starting Slack Socket Mode client")
			if err := socketClient.Run(); err != nil {
				logrus.Errorf("Socket mode error: %v", err)
			}
		}()

		go func() {
			r := gin.Default()
			r.POST("/slack/events", slackHandler.HandleEvents)
			if err := r.Run("0.0.0.0:8082"); err != nil {
				logrus.Errorf("Failed to run Gin server: %v", err)
			}
		}()
	} else {
		setupLog.Info("Slack integration disabled (missing tokens)")
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logrus.Info("Shutdown signal received")
		cancel()
	}()

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
