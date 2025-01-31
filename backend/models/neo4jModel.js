// import connection
import db from "../config/neo4j.js";

// show all Labels from Neo4jDatabase
export const modelAllLabels = (data, result) => {
  db.run("MATCH (n) RETURN distinct labels(n)")
    .then((data) => {
      result(null, data);
    })
    .catch((err) => {
      console.log(err);
      result(err, null);
    });
};

// save a new empty Label in Neo4jDatabase
export const modelSaveNewLabel = (data, result) => {
  console.log("modelSaveNewLabel => ", data);
  console.log("CREATE (n: " + data.node_text + ")");
  db.run("CREATE (n: " + data.node_text + ")")
    .then((data) => {
      result(null, data);
    })
    .catch((err) => {
      console.log(err);
      result(err, null);
    });
};

// save a new Label with Node in Neo4jDatabase
export const modelSaveNewNode = (data, result) => {
  console.log("modelSaveNewNode => ", data);
  console.log(
    "CREATE (n: " +
      data.node_label +
      " { label: '" +
      data.node_name +
      "', name: '" +
      data.node_name +
      "', info: 'Info zu " +
      data.node_info +
      "', img: '" +
      data.node_img +
      "'})"
  );

  db.run(
    "MATCH (n:" +
      data.node_label +
      ") where NOT (EXISTS (n.name)) detach delete n"
  )
    .then((data1) => {
      db.run(
        "CREATE (n: " +
          data.node_label +
          " {  label: '" +
          data.node_name +
          "', name: '" +
          data.node_name +
          "', info: 'Info zu " +
          data.node_info +
          "', img: '" +
          data.node_img +
          "'})"
      )
        .then((data) => {
          result(null, data.label);
        })
        .catch((err) => {
          console.log(err);
          result(err, null);
        });
    })
    .catch((err) => {
      console.log("delete", err);
    });
};

// show all Datas from one Node in Database
export const modelShowDataFromOneNode = (data, result) => {
  // console.log('modelShowDataFromOneNode')
  // console.log('data => ', data)
  // console.log('result => ', result)
  // console.log(">>>>>>> MATCH (n:" + data.label + "{name: " + data.name + "}) RETURN n.name LIMIT 25")

  db.run(
    "MATCH (n:" + data.label + "{name: '" + data.name + "'}) RETURN n LIMIT 25"
  )
    .then((data) => {
      result(null, data);
    })
    .catch((err) => {
      console.log(err);
      result(err, null);
    });
};

// delete a Node in Database by name
export const modelDeleteNode = (data, result) => {
  // console.log('modelDeleteNode')
  // console.log('data => ', data)
  // console.log('result => ', result)
  // console.log(">>>>>>> MATCH (n { name: '" + data.name + "' }) DETACH DELETE n")

  db.run("MATCH (n { name: '" + data.name + "' }) DETACH DELETE n")
    .then((data) => {
      result(null, data);
    })
    .catch((err) => {
      console.log(err);
      result(err, null);
    });
};

// delete a Node in Database by ID
export const modelDeleteNodeByID = (data, result) => {
  // console.log('modelDeleteNode')
  console.log("data => ", data);
  // console.log('result => ', result)
  console.log(
    ">>>>>>> MATCH (n) where id(n) = " + data.id + " DETACH DELETE n"
  );

  db.run("MATCH (n) where id(n) = " + data.id + " DETACH DELETE n")
    .then((data) => {
      result(null, data);
    })
    .catch((err) => {
      console.log(err);
      result(err, null);
    });
};
// delete all Node and relationsships in Database !! ACHTUNG ALLes wird gelöscht !!
export const modelDeleteAll = (data, result) => {
  db.run("MATCH (n) DETACH DELETE n")
    .then((data) => {
      result(null, data);
    })
    .catch((err) => {
      console.log(err);
      result(err, null);
    });
};

// MATCH (n:Person) RETURN n.name LIMIT 25

// show all Nodes from Label in Neo4jDatabase
export const modelAllNodes = (data, result) => {
  console.log("modelAllNodes => ", data);
  db.run("MATCH (n:" + data.node + ") RETURN n LIMIT 25")
    .then((data) => {
      result(null, data);
    })
    .catch((err) => {
      console.log(err);
      result(err, null);
    });
};

//save two nodes with Relationship
export const modelSaveNodesRelations = (data, result) => {
  console.log("modelSaveNodesRelations => ", data);

  db.run(
    `MATCH 
           (a:` +
      data.label1 +
      `),(b:` +
      data.label2 +
      `)
            WHERE a.name = '` +
      data.node1 +
      `' 
            AND b.name = '` +
      data.node2 +
      `' 
            CREATE (a)-[r: ` +
      data.relations +
      ` {title:'` +
      data.relations +
      `'}]->(b)  
            RETURN r`
  )
    .then((data) => {
      result(null, data);
    })
    .catch((err) => {
      console.log(err);
      result(err, null);
    });
};

// show all Relationschips
export const modelAllRelationships = (data, result) => {
  console.log("modelAllRelationships");

  db.run("MATCH (n)-[r]-(m) RETURN distinct type(r)")
    .then((data) => {
      console.log("modelAllRelationships then data => ", data);
      result(null, data);
    })
    .catch((err) => {
      console.log(err);
      result(err, null);
    });
};

// Lösche alle Knoten:personen  die keinen namen haben = null
export const modelDeleteEmptyLabels = (data, result) => {
  console.log("modelDeleteEmptyLabels => ", data);
  //console.log("MATCH (n:"+ data.node +") detach delete n")
  db.run("MATCH (n:" + data.node + ") detach delete n")
    .then((data) => {
      // console.log('modelAllRelationships then => ', data)
      result(null, data);
    })
    .catch((err) => {
      console.log(err);
      result(err, null);
    });
};

// zeichne eine Verbindung zwischen zwei Knoten
export const modelSetEdges = (data, result) => {
  console.log("modelSetEdges => ", data);
  console.log("modelSetEdges title => ", data.title);
  console.log("modelSetEdges from id => ", data.from);
  console.log("modelSetEdges to id=> ", data.to);
  // console.log('modelSetEdges query 1 => ', `MATCH
  // (a),(b)
  //  WHERE ID(a) = `+ data.from+`
  //  AND ID(b) = `+ data.to +`
  //  CREATE (a)-[r: RELATES_TO {title:'`+ data.title +`'}]->(b)
  //  RETURN r`)

  console.log(
    "modelSetEdges query 2 => ",
    `MATCH 
    (a),(b)
     WHERE ID(a) = ` +
      data.from +
      ` 
     AND ID(b) = ` +
      data.to +
      `
     CREATE (a)-[r: ` +
      data.title +
      `{title:'` +
      data.title +
      `'}]->(b)  
     RETURN r`
  );

  db.run(
    `MATCH 
           (a),(b)
            WHERE ID(a) = ` +
      data.from +
      ` 
            AND ID(b) = ` +
      data.to +
      ` 
            CREATE (a)-[r: ` +
      data.title +
      `{title:'` +
      data.title +
      `'}]->(b)  
            RETURN r`
  )
    .then((data) => {
      result(null, data);
    })
    .catch((err) => {
      console.log(err);
      result(err, null);
    });
};
