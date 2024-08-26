# Custom module to print the CQL description of an entire cluster, keyspace, or a specific table 
from os import path
import tempfile

def extractTableSchema(full_schema, keyspace_name, table_name):
    tables = full_schema.split("CREATE TABLE")
    for table in tables:
        if f"{keyspace_name}.{table_name}" in table:
            return "CREATE TABLE" + table.split(";")[0] + ";"
    return ""

def printCQLDescBackground(id, scope, session):
    cql_desc = ""    
    if scope == "cluster":
        cql_desc = session.cluster.metadata.export_schema_as_string()
    elif scope.startswith("keyspace>"):
        parts = scope.split("table>")
        keyspace = parts[0][len("keyspace>"):]
        if len(parts) == 1:  # Keyspace without table specified
            cql_desc = session.cluster.metadata.keyspaces[keyspace].export_as_string()
        else:  # Keyspace with specific table
            table = parts[1]
            keyspace_schema = session.cluster.metadata.keyspaces[keyspace].export_as_string()
            cql_desc = extractTableSchema(keyspace_schema, keyspace, table)
    file_name = path.join(tempfile.gettempdir(), f"{id}.cqldesc")
    file = open(file_name,"w")
    file.write(f"{cql_desc}")
    file.close()
