# Custom module to print the CQL description of an entire cluster, keyspace, or a specific table, or an index
from os import path
import tempfile

def extractTableSchema(full_schema, keyspace_name, table_name, index_name = None):
    try:
        tables = full_schema.split("CREATE TABLE")
        for table in tables:
            if f"{keyspace_name}.{table_name}" in table:
                if index_name is None:
                    return "CREATE TABLE" + table.split(";")[0] + ";"
                else:
                    parts = table.split(";")
                    index = list(filter(lambda statement: (index_name in statement) and ((f"{keyspace_name}.{table_name}") in statement), parts))
                    return "/* Description of the index table */\n" + "CREATE TABLE" + parts[0] + ";\n\n" + "/* Description of the index */" + index[0] + ";"
    except:
        pass
    
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
            index = table.split("index>")
            keyspace_schema = session.cluster.metadata.keyspaces[keyspace].export_as_string()
            if len(index) == 1:
                cql_desc = extractTableSchema(keyspace_schema, keyspace, table)
            else:
                cql_desc = extractTableSchema(keyspace_schema, keyspace, table[:len("index>") - 1], index[1])

    file_name = path.join(tempfile.gettempdir(), f"{id}.cqldesc")
    file = open(file_name,"w")
    file.write(f"{cql_desc}")
    file.close()
