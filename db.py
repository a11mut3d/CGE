from neo4j import GraphDatabase

class GraphDB:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="password"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.init_db()

    def init_db(self):
        with self.driver.session() as session:
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Host) REQUIRE n.id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.id IS UNIQUE")

    def save_scan(self, scan_id, domain, nodes, edges, endpoints, requests):
        with self.driver.session() as session:
            session.run("MATCH (s:Scan {id: $id}) DETACH DELETE s", id=scan_id)
            session.run("CREATE (s:Scan {id: $id, domain: $domain, timestamp: datetime()})", id=scan_id, domain=domain)
            for node in nodes:
                session.run("MERGE (h:Host {id: $id}) SET h.label = $label", id=node['id'], label=node['label'])
                session.run("MATCH (s:Scan {id: $id_scan}) MATCH (h:Host {id: $id_host}) CREATE (s)-[:INCLUDES]->(h)",
                            id_scan=scan_id, id_host=node['id'])
            for edge in edges:
                session.run("""
                    MATCH (source:Host {id: $source_id})
                    MATCH (target:Host {id: $target_id})
                    MERGE (source)-[r:COMMUNICATES {method: $method, details: $details}]->(target)
                """, source_id=edge['source'], target_id=edge['target'], method=edge['method'], details=edge['details'])
            for host, ep_list in endpoints.items():
                for ep in ep_list:
                    ep_id = f"{host}|{ep}"
                    session.run("MERGE (e:Endpoint {id: $id}) SET e.method_path = $ep, e.host = $host", id=ep_id, ep=ep, host=host)
                    session.run("MATCH (h:Host {id: $host}) MATCH (e:Endpoint {id: $ep_id}) MERGE (h)-[:HAS_ENDPOINT]->(e)",
                                host=host, ep_id=ep_id)

    def load_scan(self, scan_id):
        with self.driver.session() as session:
            if not session.run("MATCH (s:Scan {id: $id}) RETURN s", id=scan_id).single():
                return None
            nodes = [{"id": r["id"], "label": r["label"]} for r in session.run(
                "MATCH (s:Scan {id: $id})-[:INCLUDES]->(h:Host) RETURN h.id as id, h.label as label", id=scan_id)]
            edges = [{"source": r["source"], "target": r["target"], "method": r["method"], "details": r["details"]} for r in session.run(
                "MATCH (source:Host)-[r:COMMUNICATES]->(target:Host) WHERE exists((:Scan {id: $id})-[:INCLUDES]->(source)) "
                "RETURN source.id as source, target.id as target, r.method as method, r.details as details", id=scan_id)]
            endpoints = {}
            for r in session.run("MATCH (h:Host)-[:HAS_ENDPOINT]->(e:Endpoint) WHERE exists((:Scan {id: $id})-[:INCLUDES]->(h)) "
                                 "RETURN h.id as host, e.method_path as ep", id=scan_id):
                endpoints.setdefault(r["host"], []).append(r["ep"])
            return {"nodes": nodes, "edges": edges, "endpoints": endpoints}

    def list_scans(self):
        with self.driver.session() as session:
            result = session.run("MATCH (s:Scan) RETURN s.id as id, s.domain as domain, s.timestamp as timestamp ORDER BY s.timestamp DESC")
            return [{"id": r["id"], "domain": r["domain"], "timestamp": str(r["timestamp"])} for r in result]

    def close(self):
        self.driver.close()
