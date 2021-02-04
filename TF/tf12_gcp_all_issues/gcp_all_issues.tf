resource "google_container_cluster" "primary" {
  provider = google
  name = "my-gke-cluster"
  location = "us-central1"
  initial_node_count = 1
  // GCP Kubernetes Engine Clusters have Legacy Authorization enabled
  // $.resource[*].google_container_cluster.*.*[*].enable_legacy_abac anyTrue
  enable_legacy_abac = true

  //??? GCP Kubernetes Engine Clusters have Master authorized networks disabled
  //$.resource[*].google_container_cluster[*].*.*.master_authorized_networks_config anyNull
  master_authorized_networks_config {
  }
  //GCP Kubernetes Engine Clusters not configured with private cluster
  //$.resource[*].google_container_cluster exists and  ($.resource[*].google_container_cluster.*[*].*.private_cluster_config anyNull or $.resource[*].google_container_cluster.*[*].*.private_cluster_config[*].enable_private_nodes anyNull or $.resource[*].google_container_cluster.*[*].*.private_cluster_config[*].enable_private_nodes anyFalse)
  private_cluster_config {
    enable_private_endpoint = false
    enable_private_nodes = false
  }

  network_policy {
    enabled = true
    provider = "CALICO"
  }
  // GCP Kubernetes Engine Clusters have Network policy disableds
  // $.resource[*].google_container_cluster exists and  ($.resource[*].google_container_cluster.*[*].*.network_policy anyNull or $.resource[*].google_container_cluster.*[*].*.addons_config[*].network_policy_config anyNull or $.resource[*].google_container_cluster.*[*].*.addons_config[*].network_policy_config[*].disabled anyNull or $.resource[*].google_container_cluster.*[*].*.addons_config[*].network_policy_config[*].disabled anyTrue)
  addons_config {
    network_policy_config {
      disabled = true
    }
    // GCP Kubernetes cluster istioConfig not enabled
    // $.resource[*].google_container_cluster exists and ($.resource[*].google_container_cluster.*[*].*.addons_config anyNull or $.resource[*].google_container_cluster.*[*].*.addons_config[*].istio_config anyNull or $.resource[*].google_container_cluster.*[*].*.addons_config[*].istio_config[*] anyNull  or  $.resource[*].google_container_cluster.*[*].*.addons_config[*].istio_config[*].disabled anyNull or  $.resource[*].google_container_cluster.*[*].*.addons_config[*].istio_config[*].disabled anyTrue)
    //    istio_config {
    //      disabled = true
    //    }
    // GCP Kubernetes Engine Clusters have HTTP load balancing disabled
    // $.resource[*].google_container_cluster exists and ($.resource[*].google_container_cluster.*[*].*.addons_config[*].http_load_balancing[*].disabled anyTrue)
    http_load_balancing {
      disabled = true
    }

    // GCP Kubernetes Engine Clusters web UI/Dashboard is set to Enabled
    // $.resource[*].google_container_cluster exists and $.resource[*].google_container_cluster.*[*].*.addons_config[*].kubernetes_dashboard[*].disabled anyFalse
    //    kubernetes_dashboard {
    //      disabled = false
    //    }
  }

  //GCP Kubernetes cluster Application-layer Secrets not encrypteds
  //$.resource[*].google_container_cluster exists and ($.resource[*].google_container_cluster[*].*[*].database_encryption anyNull or  $.resource[*].google_container_cluster[*].*[*].database_encryption[*].state any equal DECRYPTED)
  database_encryption {
    state = "DECRYPTED"
    key_name = "key"
  }

  // GCP Kubernetes Engine Clusters have Alias IP disabled
  // $.resource[*].google_container_cluster exists and $.resource[*].google_container_cluster[*].*.*.ip_allocation_policy does not exist
  //  ip_allocation_policy {
  //  cluster_ipv4_cidr_block = "10.32.0.0/14"
  //  services_ipv4_cidr_block = "10.0.0.0/20"
  //  }

  node_config {
    // GCP Kubernetes Engine Cluster Nodes have default Service account for Project access
    // $.resource[*].google_container_cluster[*].*[*].node_config anyNull or $.resource[*].google_container_cluster[*].*[*].node_config[*].service_account anyNull
    //    service_account = "default"
    preemptible = true
    machine_type = "e2-medium"

    metadata = {
      disable-legacy-endpoints = "true"
    }

    oauth_scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring",
    ]
  }

  // GCP Kubernetes Engine Clusters have pod security policy disabled
  // $.resource[*].google_container_cluster.*[*].*.pod_security_policy_config anyNull or $.resource[*].google_container_cluster.*[*].*.pod_security_policy_config.enabled anyFalse
  //  pod_security_policy_config {
  //    enabled = false
  //  }

  master_auth {
    //GCP Kubernetes Engine Clusters Basic Authentication is set to Enabled
    //$.resource.*.google_container_cluster.*.*.*.master_auth exists and not ($.resource.*.google_container_cluster.*.*.*.master_auth.*.password is empty and $.resource.*.google_container_cluster.*.*.*.master_auth.*.username is empty)
    username = "abc"
    password = ""

    //GCP Kubernetes Engine Clusters Client Certificate is set to Disabled
    //$.resource[*].google_container_cluster[*].*.*.master_auth[*].client_certificate_config[*].issue_client_certificate anyTrue
    client_certificate_config {
      issue_client_certificate = true
    }
  }
}


resource "google_container_node_pool" "primary_preemptible_nodes" {
  name = "my-node-pool"
  location = "us-central1"
  cluster = google_container_cluster.primary.name
  node_count = 1

  node_config {
    preemptible = true
    machine_type = "e2-medium"
    //GCP Kubernetes Engine Clusters not using Container-Optimized OS for Node image
    //$.resource[*].google_container_node_pool exists and  ($.resource[*].google_container_node_pool.*[*].*.node_config anyNull or $.resource[*].google_container_node_pool.*[*].*.node_config[*].image_type anyNull or  not $.resource[*].google_container_node_pool.*[*].*.node_config[*].image_type allStartWith  cos )
    image_type = "2cos"

    oauth_scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring",
    ]
  }
}

resource "google_storage_bucket" "static-site" {
  name = "image-store.com"
  location = "EU"
  force_destroy = true

  uniform_bucket_level_access = true
  //GCP Storage log buckets have object versioning disabled
  //$.resource[*].google_storage_bucket exists and ($.resource[*].google_storage_bucket.*[*].*.versioning anyNull or $.resource[*].google_storage_bucket.*[*].*.versioning[*].enabled anyNull or $.resource[*].google_storage_bucket.*[*].*.versioning[*].enabled anyFalse)
  versioning {
    enabled = false
  }
  //  Storage Bucket does not have Access and Storage Logging enabled
  //$.resource[*].google_storage_bucket exists and ($.resource[*].google_storage_bucket.*[*].*.logging anyNull or $.resource[*].google_storage_bucket.*[*].*.logging[*].log_bucket anyEmpty)
  //  logging {
  //    log_bucket = ""
  //  }
}

//GCP Storage buckets are publicly accessible to all authenticated users
//$.resource[*].google_storage_bucket_access_control[*].*[*].entity contains allUsers
resource "google_storage_bucket_access_control" "public_rule" {
  bucket = google_storage_bucket.static-site.name
  role = "READER"
  entity = "allUsers"
}

resource "google_storage_bucket_access_control" "public_rule2" {
  bucket = google_storage_bucket.bucket.name
  role = "READER"
  entity = "allUsers"
}

resource "google_storage_bucket" "bucket" {
  name = "static-content-bucket"
}

//SQL Instances do not have SSL configured
//$.resource[*].google_sql_database_instance exists and $.resource[*].google_sql_ssl_cert !exists
//resource "google_sql_ssl_cert" "client_cert" {
//  common_name = "client-name"
//  instance = google_sql_database_instance.master.name
//}

//SQL Instances with network authorization exposing them to the Internet
//$.resource[*].google_sql_database_instance[*].*[*].settings[*].ip_configuration[*].authorized_networks[*].value anyEqual 0.0.0.0/0 or $.resource[*].google_sql_database_instance[*].*[*].settings[*].ip_configuration[*].authorized_networks[*].value anyEqual ::/0
resource "google_sql_database_instance" "master" {
  name = "master-instance"
  database_version = "POSTGRES_11"
  region = "us-central1"

  settings {
    # Second-generation instance tiers are based on the machine
    # type. See argument reference below.
    tier = "db-f1-micro"
  }
}
resource "google_compute_instance" "apps" {
  count = 8
  name = "apps-${count.index + 1}"
  machine_type = "f1-micro"

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-1804-lts"
    }
  }

  network_interface {
    network = "default"

    access_config {
      // Ephemeral IP
    }
  }
}

resource "random_id" "db_name_suffix" {
  byte_length = 4
}

locals {
  onprem = [
    "0.0.0.0/0",
    "::/0"]
}

resource "google_sql_database_instance" "postgres" {
  name = "postgres-instance-${random_id.db_name_suffix.hex}"
  database_version = "POSTGRES_11"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      //SQL Instances with network authorization exposing them to the Internet
      // $.resource[*].google_sql_database_instance[*].*[*].settings[*].ip_configuration[*].authorized_networks[*].value anyEqual 0.0.0.0/0 or $.resource[*].google_sql_database_instance[*].*[*].settings[*].ip_configuration[*].authorized_networks[*].value anyEqual ::/0
      dynamic "authorized_networks" {
        for_each = google_compute_instance.apps
        iterator = apps

        content {
          name = apps.value.name
          value = apps.value.network_interface.0.access_config.0.nat_ip
        }
      }

      dynamic "authorized_networks" {
        for_each = local.onprem
        iterator = onprem

        content {
          name = "onprem-${onprem.key}"
          value = onprem.value
        }
      }
    }
  }
}

//GCP User managed service accounts have user managed service account keys
//$.resource[*].google_service_account_key[*].*[*].service_account_id contains google_service_account or $.resource[*].google_service_account_key[*].*[*].service_account_id any end with iam.gserviceaccount.com
resource "google_service_account_key" "mykey" {
  service_account_id = "iam.gserviceaccount.com"
  public_key_type = "TYPE_X509_PEM_FILE"
}

//GCP VM disks not encrypted with Customer-Supplied Encryption Keys (CSEK)
//$.resource[*].google_compute_disk exists and $.resource[*].google_compute_disk.*.[*].*.disk_encrypt_key does not exist
resource "google_compute_disk" "default" {
  name = "test-disk"
  type = "pd-ssd"
  zone = "us-central1-a"
  image = "debian-8-jessie-v20170523"
  labels = {
    environment = "dev"
  }
  physical_block_size_bytes = 4096
}

//GCP VM instances have IP forwarding enabled
//$.resource[*].google_compute_instance_template[*].*.[*].can_ip_forward anyTrue
resource "google_compute_instance_template" "instance_template" {
  name_prefix = "instance-template-"
  machine_type = "n1-standard-1"
  region = "us-central1"

  can_ip_forward = true

  // boot disk
  disk {
    # ...
  }

  // networking
  network_interface {
    # ...
  }

  lifecycle {
    create_before_destroy = true
  }
}

//GCP VPC Network subnets have Private Google access disabled
//$.resource[*].google_compute_subnetwork[*].*[*].private_ip_google_access anyNull or $.resource[*].google_compute_subnetwork[*].*[*].private_ip_google_access anyFalse
resource "google_compute_subnetwork" "network-with-private-secondary-ip-ranges" {
  name = "test-subnetwork"
  ip_cidr_range = "10.2.0.0/16"
  region = "us-central1"
  network = google_compute_network.custom-test.id
  private_ip_google_access = false
  secondary_ip_range {
    range_name = "tf-test-secondary-range-update1"
    ip_cidr_range = "192.168.10.0/24"
  }
}
resource "google_compute_network" "custom-test" {
  name = "test-network"
  auto_create_subnetworks = false
}

//GCP Kubernetes Engine Clusters using the default network
//$.resource[*].google_project[*].*[*].auto_create_network anyTrue or  $.resource[*].google_project[*].*[*].auto_create_network anyNull
resource "google_project" "my_project" {
  name = "My Project"
  project_id = "your-project-id"
  org_id = "1234567"
  auto_create_network = true
}

//GCP Projects have OS Login disabled
//$.resource[*].google_compute_project_metadata_item.[*].[*].[*].key exists and $.resource[*].google_compute_project_metadata_item.[*].[*].[*].key == enable-oslogin and $.resource[*].google_compute_project_metadata_item.[*].[*].[*].value exists and $.resource[*].google_compute_project_metadata_item.[*].[*].[*].value == FALSE
resource "google_compute_project_metadata_item" "default" {
  key = "enable-oslogin"
  value = "FALSE"
}

//GCP IAM Service account has admin privileges
//GCP IAM user with service account privileges
//GCP IAM user have overly permissive Cloud KMS roles
data "google_iam_policy" "admin" {
  binding {
    role = "roles/editor"
    members = [
      "serviceAccount:your-custom-sa@your-project.iam.gserviceaccount.com",
    ]
  }
  binding {
    role = "roles/iam.serviceAccountUser"
    members = [
      "user:abc@gmail.com",
    ]
  }
  binding {
    role = "roles/cloudkms.admin"
    members = [
      "user:abc@gmail.com",
    ]
  }
}
resource "google_project_iam_member" "sql_client" {
    role = "roles/editor"
    member = "serviceAccount:your-custom-sa@your-project.iam.gserviceaccount.com"
}
resource "google_project_iam_member" "sql_client2" {
    role = "roles/iam.serviceAccountUser"
    member = "user:abc@gmail.com"
}
resource "google_project_iam_member" "sql_client3" {
    role = "roles/cloudkms.admin"
    member = "user:abc@gmail.com"
}