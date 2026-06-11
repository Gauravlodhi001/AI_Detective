const INTROSPECTION_QUERY = `
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      fields {
        name
        args {
          name
          type {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
        type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}
`;

class GraphQLParser {
  constructor(log) {
    this.log = log || [];
  }

  // Sends the introspection query to the endpoint
  async fetchSchema(requestFn, graphqlUrl, headers = {}) {
    this.log.push(`[GraphQL] Sending Introspection query to: ${graphqlUrl}`);
    const res = await requestFn(graphqlUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...headers
      },
      body: JSON.stringify({ query: INTROSPECTION_QUERY })
    });

    if (res.status !== 200) {
      this.log.push(`[GraphQL] Introspection failed with HTTP ${res.status}`);
      return null;
    }

    try {
      const data = JSON.parse(res.body);
      if (data && data.data && data.data.__schema) {
        this.log.push(`[GraphQL] Schema successfully retrieved.`);
        return data.data.__schema;
      }
      this.log.push(`[GraphQL] Response JSON structure did not match introspection schema.`);
    } catch (e) {
      this.log.push(`[GraphQL] Error parsing response body as JSON: ${e.message}`);
    }
    return null;
  }

  // Parses the schema and generates a list of testable endpoints (query/mutation templates)
  generateTestOperations(schema) {
    if (!schema) return [];
    
    const types = schema.types || [];
    const queryTypeName = schema.queryType ? schema.queryType.name : 'Query';
    const mutationTypeName = schema.mutationType ? schema.mutationType.name : 'Mutation';

    const queryType = types.find(t => t.name === queryTypeName);
    const mutationType = types.find(t => t.name === mutationTypeName);

    const testOperations = [];

    // Helper to find simple scalar subfields of a composite type
    const findSubfields = (typeName) => {
      const targetType = types.find(t => t.name === typeName);
      if (!targetType || !targetType.fields) return 'id';
      
      const scalarFields = targetType.fields
        .filter(f => {
          // Keep only scalar/simple types to avoid deep nesting
          const kind = f.type.kind || (f.type.ofType && f.type.ofType.kind);
          return kind === 'SCALAR' || kind === 'NON_NULL';
        })
        .slice(0, 3)
        .map(f => f.name);
      
      return scalarFields.length > 0 ? scalarFields.join(' ') : 'id';
    };

    // Helper to extract type name from type structure (handling NON_NULL and LIST)
    const getBaseTypeName = (typeObj) => {
      let current = typeObj;
      while (current && current.ofType) {
        current = current.ofType;
      }
      return current ? current.name : null;
    };

    const processFields = (fields, opType) => {
      if (!fields) return;
      for (const field of fields) {
        const opName = field.name;
        const args = field.args || [];
        const baseReturnType = getBaseTypeName(field.type);
        const returnKind = field.type.kind || (field.type.ofType && field.type.ofType.kind);
        
        let subfieldsStr = '';
        if (returnKind === 'OBJECT' || (field.type.ofType && getBaseTypeName(field.type) && returnKind !== 'SCALAR')) {
          const subfields = findSubfields(baseReturnType);
          subfieldsStr = `{ ${subfields} }`;
        }

        // Build mock arguments
        const argStrings = [];
        const templateArgs = [];

        args.forEach(arg => {
          const argName = arg.name;
          const argType = getBaseTypeName(arg.type);
          
          let mockVal = 'null';
          if (argType === 'String') {
            mockVal = '"{{VALUE}}"'; // Injection marker
          } else if (argType === 'Int' || argType === 'Float') {
            mockVal = '1';
          } else if (argType === 'Boolean') {
            mockVal = 'true';
          } else if (argType === 'ID') {
            mockVal = '"1"';
          }

          argStrings.push(`${argName}: ${mockVal}`);
          templateArgs.push({ name: argName, type: argType, placeholder: mockVal });
        });

        const argList = argStrings.length > 0 ? `(${argStrings.join(', ')})` : '';
        const queryBody = `${opType} { ${opName}${argList} ${subfieldsStr} }`;

        testOperations.push({
          type: opType,
          name: opName,
          query: queryBody,
          arguments: templateArgs
        });
      }
    };

    if (queryType && queryType.fields) {
      processFields(queryType.fields, 'query');
    }
    if (mutationType && mutationType.fields) {
      processFields(mutationType.fields, 'mutation');
    }

    this.log.push(`[GraphQL] Generated ${testOperations.length} testable operations.`);
    return testOperations;
  }
}

module.exports = { GraphQLParser };
