package plan

// statefulTypes lists the Terraform resource types that hold data at rest and
// therefore pin that data to a geography. It is deliberately a curated list and
// not a heuristic: a residency review that guesses at what stores data produces
// findings nobody can act on.
//
// This is a cloud-topology fact, not a legal one — it carries no source_url and
// is not part of a jurisdiction ruleset.
var statefulTypes = map[string]bool{
	// AWS
	"aws_backup_vault":                  true,
	"aws_db_instance":                   true,
	"aws_docdb_cluster":                 true,
	"aws_dynamodb_table":                true,
	"aws_ebs_volume":                    true,
	"aws_efs_file_system":               true,
	"aws_elasticache_cluster":           true,
	"aws_elasticache_replication_group": true,
	"aws_fsx_lustre_file_system":        true,
	"aws_fsx_windows_file_system":       true,
	"aws_glacier_vault":                 true,
	"aws_kinesis_stream":                true,
	"aws_memorydb_cluster":              true,
	"aws_neptune_cluster":               true,
	"aws_opensearch_domain":             true,
	"aws_qldb_ledger":                   true,
	"aws_rds_cluster":                   true,
	"aws_redshift_cluster":              true,
	"aws_s3_bucket":                     true,
	"aws_sqs_queue":                     true,
	"aws_timestreamwrite_table":         true,

	// Azure
	"azurerm_cosmosdb_account":           true,
	"azurerm_eventhub_namespace":         true,
	"azurerm_key_vault":                  true,
	"azurerm_managed_disk":               true,
	"azurerm_mssql_database":             true,
	"azurerm_mssql_server":               true,
	"azurerm_mysql_flexible_server":      true,
	"azurerm_postgresql_flexible_server": true,
	"azurerm_redis_cache":                true,
	"azurerm_servicebus_namespace":       true,
	"azurerm_storage_account":            true,
	"azurerm_storage_share":              true,
	"azurerm_synapse_workspace":          true,

	// GCP
	"google_bigquery_dataset":      true,
	"google_bigtable_instance":     true,
	"google_compute_disk":          true,
	"google_filestore_instance":    true,
	"google_firestore_database":    true,
	"google_pubsub_topic":          true,
	"google_redis_instance":        true,
	"google_spanner_instance":      true,
	"google_sql_database_instance": true,
	"google_storage_bucket":        true,

	// OCI
	"oci_core_volume":                  true,
	"oci_database_autonomous_database": true,
	"oci_database_db_system":           true,
	"oci_file_storage_file_system":     true,
	"oci_mysql_mysql_db_system":        true,
	"oci_nosql_table":                  true,
	"oci_objectstorage_bucket":         true,
	"oci_streaming_stream":             true,
}

// IsStateful reports whether a resource type stores data at rest.
func IsStateful(resourceType string) bool { return statefulTypes[resourceType] }
