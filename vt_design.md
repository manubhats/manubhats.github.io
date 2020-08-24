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
 2. The API microservice running on the pods in Fargate handles file uploads to S3
 3. Publish the message to SNS pub/sub upon successful file upload
 4. The same services after reading the file and running the scripts can upload the metadata to DynamoDB
 5. Kubernetes cluster is running python scripts that reads from SNS pub/sub and runs scans for those AV that are supported on linux based OS
 6. Kubernetes based windows cluster is supported on AWS and can run the required python scripts to read from SNS and runs scans for AV supported only on windows
 7. Metrics sent to Prometheus and viewed on Grafana Dashboards
 
## Authorization and Authentication
 JSON Web Tokens are used for authentication in the HTTP Bearer header. Each user has a user ID, a public API access token and secret key for signing each JWT using HMAC SHA256. For each request, the API token is sent as part of the JWT payload.

#### JWT Contains 3 parts:
> Header: 
 `{
  "alg": "HS256",
  "typ": "JWT"
}`

> Payload
`{
  "public_api_token": "1kj21312351fsr11232fsd1551fsf3",
  "UserID": "21fdszfasf334512341"
}`

> secret key used for signature
#### Steps
1. Once the API service receives a request from the user, it reads the API token from the payload on JWT
2. Uses the API token to fetch UserID and Secret key from Redis
3. Uses the retrieved secret key to verify JWT signature 

## Backend API - Microservices

The API service can be written in Node.js+TypeScript or Golang using appropriate web frameworks. For this use case, we can choose Node.js, an efficient non-blocking and asynchronous web server that can handle requests at scale.

##  Scanning Scripts and AV Services

 - Most scanning scripts and services run on linux based docker containers, however, some would only run Windows OS or other OS. This means that we need to have a Kubernetes cluster running windows for windows based workloads. 
 
 - If there is a requirement for an OS currently not supported on AWS containers, one could provision an EC2 machine and load the OS for these scans.

 - Scripts can be written in Python and bundled as a Python package. Each AntiVirus scan and its required resources can be bundled into a package and versioned into a repository for easy management.
 
 - A successful file upload triggers a message to SNS and this is picked up by the containers and/or VMs subscribed to this topic. The SNS (Pub/Sub) message should contain at least the `<Username>:<MD5>` for the scripts to read and scan these files form the data store. 
 
 - The results are then sent to the backend API server which are then parsed, required information extracted and committed to the database and also returned to the user.

## Cloud Watch Logs
The logs of the API service and all the containers running the scanning scripts can be sent to cloudwatch logs for easy and quick debugging capabilities.

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


## Data Models
Data layer consists of ElasticCache using Redis for efficient session management and DynamoDB for storing file metadata and scan results.

### DynamoDB Schema
We can use a single table design to store all the required information. This means that we would need nested attributes for some of the attributes within the table.
#### Table: UserFileMetadata

Primary Key = Partition Key + Sort Key
Sample FileID = 0bf01094f5c699046d8228a8f5d5754ea454e5e58b4e6151fef37f32c83f6497

 - ** UserID (SHA256 of username)** - PARTITION KEY
 - **FileID(MD5 of file)** - SORT KEY
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
	 -   TrId
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

			
## API

### File upload(and analyse)

Uploading files for scanning is the primary function. The below route handles the file uploads and starts a scan.

- API service running on Fargate verifies the API key for each request. Reads Username and Secret key from ElasticCache(Redis).
-  Writes file to cloud storage
    -   The MD5 and SHA256 are calculated and file upload begins
    -   If the file already exists, a scan of the existing file is started
    -   Upon successful upload the file is names to `<Username>:<MD5>`
-  Store initial metadata for file after successful upload to DynamoDB
-  Publish to the SNS topic after the file has completed
- At each step an error is reported if it fails
#### Request
```
PUT /api/v1/files

Bearer: <JWT>
Request Body: <Multi-part upload>
```
#### Sample Response
```
{
   "data":{
      "type":"analysis",
      "id":"NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw=="
   }
}
```

### Download a file
Users may occasionally want to download a file that they have scanned. The below API route can be used for this purpose.

#### Request
```
GET /api/v1/files/{id}/download

Bearer: <JWT>
```
### Re-analyse a file already in VirusTotal
#### Request
```
POST /api/v3/files/{id}/analyse

Bearer: <JWT>
```
#### Sample Response
```
{
   "data":{
      "type":"analysis",
      "id":"NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw=="
   }
}
```
### Scan status

Returns the status of a particular scan.

####  Request

```
GET /api/v1/files/8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85/scans/23782907443984360149

Bearer: <JWT>
```

#### Sample Response

```
{
	“scanid”: “23782907443984360149”,
	“timestamp”: “2020-08-24T05:57:28Z”,
	“status”: “complete”,
}
```
### List Scans
Users can use the below API to list all the scans done on a particular file.
#### Request
```
GET /api/v1/files/8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85/scans/

Bearer: <JWT>
```

#### Response
```
[
	{
		"scanid": "1534290748465276123450",
		"timestamp": "2020-08-24T06:55:05.32Z",
		"status": "in-progress",
    },
    {
		"scanid": "17908575832061616499",
		"timestamp": "2020-08-24T06:57:28Z",
    	"status": "complete",
    },
]
```

### Retrieve information about a file
Users can use the below API route to get all the details of a particular file.

#### Request
```
GET	/api/v3/files/{id}
Bearer: <JWT>
```
#### Sample Response
```
{    
  "type": "file",
  "id": "8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85",
  "links": {
    "self": "https://www.virustotal.com/api/v3/files/8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85"
  },
  "data": {
    "attributes": {
      "first_seen_itw_date": 1075654056,
      "first_submission_date": 1170892383,
      "last_analysis_date": 1502355193,
      "last_analysis_results": {
        "AVG": {
          "category": "undetected",
          "engine_name": "AVG",
          "engine_update": "20170810",
          "engine_version": "8.0.1489.320",
          "method": "blacklist",
          "result": null
        }
        ...
      },
      "last_analysis_stats": {
        "harmless": 0,
        "malicious": 0,
        "suspicious": 0,
        "timeout": 0,
        "type-unsupported": 8,
        "undetected": 59
      },
      "last_submission_date": 1502355193,
      "magic": "data",
      "md5": "76cdb2bad9582d23c1f6f4d868218d6c",
      "names": [
        "zipnew.dat",
        "327916-1502345099.zip",
        "ac3plug.zip",
        "IMG_6937.zip",
        "DOC952.zip",
        "20170801486960.zip"
      ],
      "nsrl_info": {
        "filenames": [
          "WINDOWS DIALUP.ZIP",
          "kemsetup.ZIP",
          "Data_Linux.zip",
          "2003.zip",
          "_6A271FB199E041FC82F4D282E68B01D6"
        ],
        "products": [
          "Master Hacker Internet Terrorism (Core Publishing Inc.)",
          "Read Rabbits Math Ages 6-9 (Smart Saver)",
          "Neverwinter Nights Gold (Atari)",
          "Limited Edition Print Workshop 2004 (ValuSoft)",
          "Crysis (Electronic Arts Inc.)"
        ]
      },
      "reputation": -889,
      "sha1": "b04f3ee8f5e43fa3b162981b50bb72fe1acabb33",
      "sha256": "8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85",
      "size": 22,
      "ssdeep": "3:pjt/l:Nt",
      "tags": [
        "software-collection",
        "nsrl",
        "attachment",
        "trusted",
        "via-tor"
      ],
      "times_submitted": 26471,
      "total_votes": {
        "harmless": 639,
        "malicious": 958
      },
      "trid": [
        {
          "file_type": "ZIP compressed archive (empty)",
          "probability": 100
        }
      ],
      "trusted_verdict": {
        "filename": "lprn_spotlightstory_015.zip",
        "link": "https://dl.google.com/dl/spotlight/test/lprn_spotlightstory/9/lprn_spotlightstory_015.zip",
        "organization": "Google",
        "verdict": "goodware"
      },
      "type_description": "unknown",
      }
    }
  }
}
```

### References
- [AWS ALB for Fargate](https://aws.amazon.com/blogs/containers/using-alb-ingress-controller-with-amazon-eks-on-fargate/)
- [DynamoDB Core Components](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.CoreComponents.html)
-  [Monitoring Fargate Cluster](https://aws.amazon.com/blogs/containers/monitoring-amazon-eks-on-aws-fargate-using-prometheus-and-grafana/)
