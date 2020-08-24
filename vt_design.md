# VirusTotal Design

VirusTotal is a service that analyzes suspicious files and facilitates real-time detection of viruses, worms, trojans and malware content. It also manages and displays the metadata after the analysis has been completed.

## Architecture

  >Insert diagram here

## Components
The proposed design for the virus total clone consists of several managed services available on Amazon Web Services.

-  **Load Balancer**:  Amazon Elastic Load Balancer
-  **Event Stream**: Amazon Simple Notification Service
-  **Session Management**: Amazon ElastiCache for Redis
-  **Cluster Management**: Managed Kubernetes Cluster - AWS Fargate
	 - Frontend user interface: Web UI containers
	 - Backend services: File upload, processing and scanning services run on containers	 
-  **File Storage**: Amazon S3
-  **Metadata Storage**: Amazon DynamoDB
-  **Monitoring and Metrics Collection**
-  **Logs and debugging**: AWS Cloudwatch Logs

## High level flow of requests 

 1. Load Balancer handles the initial request and routes it to Fargate pods
 2. FileManagement microservice running on the pods in Fargate handles file uploads to S3
 3. Publish the message to SNS pub/sub
 4. Kubernetes Fargate cluster is running containers to read from SNS pub/sub and run the scripts on the uploaded file
 5. The same services after reading the file and running the scripts can upload the metadata to DynamoDB
 6. Metrics sent to Prometheus and viewed on Grafana Dashboards
 
## User Interface

 - The web interface allows users to easily manage and scan files as well as view the metadata for completed scans.
 
 - The interface can have a real-time progress of the scan could be monitored by watching the logs as each script is ran. If a script fails the file continues being processed however, the error will be reported and logged.
 
 - Users should be able to browse all their files and explore the history of each upload. They should be able to click on a file and see a list of all the scans performed on the file. They should also be able to access the results of a specific scan from the list.
 
 - Each scan can outline all the script results as well as the historical logs for each script.
 
## Monitoring and Metrics
 
 Prometheus collects metrics via a pull model over HTTP. In Kubernetes, Prometheus can automatically discover targets using Kubernetes API, targets can be pods, DaemonSets, Nodes, etc. A typical Prometheus installation in Kubernetes includes these components:

-   Prometheus server
-   Node exporter
-   Push gateway
-   Alert manager
-   kube-state-metrics (installed by default if you use  [stable/prometheus](https://github.com/helm/charts/tree/master/stable/prometheus)  helm chart)

In Kubernetes, the Prometheus server runs as a pod that is responsible for scraping metrics from metrics endpoints.

[Node exporter](https://github.com/prometheus/node_exporter)  runs as a DaemonSet and is responsible for collecting  [metrics](https://github.com/prometheus/node_exporter#enabled-by-default)  of the host it runs on. Most of these metrics are low-level operating system metrics like vCPU, memory, network, disk (of the host machine, not containers), and hardware statistics, etc. These metrics are inaccessible to Fargate customers since AWS is responsible for the health of the host machine.

To measure the performance of a pod running on Fargate, we need metrics like vCPU, memory usage, and network transfers. Prometheus collects these metrics from two sources: cAdvisor and kube-state-metrics.

##  Metadata and Scanning Services

Most scanning scripts and services run on linux based docker containers, however, some would only run Windows OS.
This means that we need to have an EC2 based windows auto scaling cluster for windows based workloads.

## Data Models
Data layer consists of ElasticCache using Redis for efficient session management and DynamoDB for storing file metadata and scan results.

### DynamoDB Schema
We can use a single table design to store all the required information. This means that we would need nested attributes for some of the attributes within the table.
#### Table: UserFileMetadata

Primary Key = Partition Key + Sort Key
FileID  = MD5:EPOCH_TIME 	   

 - **Username** - PARTITION KEY
 - **FileID** - SORT KEY
- **UserInfo**
	 - Email
	 - CreatedAt
	 - LastLogin
 - **Api**
	 - ApiKey 
	 - AcessLevel
 - **Session**
	- isActive
	-  SessionID
	- LastLogin	 
- **FileMetadata**
	-   MD5
	-   SHA1
	-   SHA256
	-   Filename
	-   Size
	-   Tags
	-   FileType
- **FileHistory**
	- CreationTime
	- FirstSubmission
	- LastSubmission
	- LastAnalysis
- **ScanResults**
	-   **PE Header Information**
	-   **PE Sections**
	    -   MD5: JSON
	-   **PE resources by type**
	    -   Type : Count
	- **PE Imports**
	- **PE Contained Resources**
		- SHA256: JSON
	- **Detection**
		- AntiVirus: JSON

			
    










### References
- [AWS ALB for Fargate](https://aws.amazon.com/blogs/containers/using-alb-ingress-controller-with-amazon-eks-on-fargate/)
- [DynamoDB Core Components](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.CoreComponents.html)
-  [Monitoring Fargate Cluster](https://aws.amazon.com/blogs/containers/monitoring-amazon-eks-on-aws-fargate-using-prometheus-and-grafana/)
- 
