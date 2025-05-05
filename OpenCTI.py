import requests
import json

# 載入 MITRE ATT&CK JSON 檔案
try:
    with open('enterprise-attack.json', 'r') as file:
        mitre_data = json.load(file)
except FileNotFoundError:
    print("錯誤: 找不到 enterprise-attack.json 檔案")
    mitre_data = {'objects': []}
except json.JSONDecodeError:
    print("錯誤: enterprise-attack.json 檔案格式無效")
    mitre_data = {'objects': []}

def get_attack_pattern_name(mitre_id):
    """
    根據 MITRE ID 從 enterprise-attack.json 中查找攻擊手法名稱。

    Args:
        mitre_id (str): MITRE ATT&CK 的 ID（例如 "T1071.004"）。

    Returns:
        str: 攻擊手法名稱，若未找到則返回 "未找到名稱"。
    """
    for obj in mitre_data['objects']:
        if obj['type'] == 'attack-pattern':
            for ref in obj.get('external_references', []):
                if ref.get('external_id') == mitre_id:
                    return obj['name']
    return "未找到名稱"

def generate_intrusion_set_query(intrusion_set_name, toTypes):
    """
    生成查詢指定入侵集合的 GraphQL 查詢字符串，使用 rf 前綴。

    Args:
        intrusion_set_name (str): 要查詢的攻擊組織名稱（例如 "APT41"）。
        toTypes (list): 查詢的目標類型（例如 ["Attack-Pattern", "Malware"] 或 ["Country", "Sector"]）。

    Returns:
        str: 格式化後的 GraphQL 查詢字符串。
    """
    safe_name = intrusion_set_name.replace('"', '\\"')
    toTypes_str = "[" + ", ".join(f'"{t}"' for t in toTypes) + "]"
    query = rf"""
    query IntrusionSet {{
       intrusionSets(
        filters: {{
          mode: or  
          filters: [
            {{
              key: ["name"]  
              values: ["{safe_name}"]
              operator: eq
              mode: and
            }}
          ]
          filterGroups: []
        }}
        first: 1
      ) 
      {{
        edges {{
          node {{
            id
            name
            aliases
            stixCoreRelationships(
              first: 50
              toTypes: {toTypes_str}
            ) {{
              edges {{
                node {{
                  to {{
                    ... on AttackPattern {{
                      entity_type
                      id
                      x_mitre_id
                    }}
                    ... on Malware {{
                      entity_type
                      id
                      name
                    }}
                    ... on Country {{
                      entity_type
                      name
                    }}
                    ... on Sector {{
                      entity_type
                      name
                    }}
                  }}
                }}
              }}
            }}
          }}
        }}
      }}
    }}
    """
    return query

def query_IntrusionSet(intrusion_set_name, opencti_url, opencti_token):
    """
    查詢 OpenCTI 的 IntrusionSet，執行兩次查詢（Attack-Pattern/Malware 和 Country/Sector），合併並去重顯示關係，返回 Attack-Pattern 和 Malware 的 ID。

    Args:
        intrusion_set_name (str): 要查詢的攻擊組織名稱。
        opencti_url (str): OpenCTI 的 GraphQL API 端點。
        opencti_token (str): OpenCTI 的認證令牌。

    Returns:
        tuple: (attack_pattern_ids, malware_ids)，包含 Attack-Pattern 和 Malware 的 ID 列表。
    """
    attack_pattern_ids = []
    malware_ids = []
    all_relationships = []

    # 第一次查詢：Attack-Pattern 和 Malware
    query1 = generate_intrusion_set_query(intrusion_set_name, ["Attack-Pattern", "Malware"])
    response1 = requests.post(
        f"{opencti_url}/graphql",
        headers={
            "Authorization": f"Bearer {opencti_token}",
            "Content-Type": "application/json",
        },
        json={"query": query1}
    )

    intrusion_set_name_result = None
    aliases = []

    if response1.status_code == 200:
        data = response1.json()
        if "errors" in data:
            print("GraphQL 錯誤 (Attack-Pattern/Malware):")
            for error in data["errors"]:
                print(error["message"])
        else:
            intrusion_sets = data.get("data", {}).get("intrusionSets")
            if intrusion_sets and intrusion_sets.get("edges"):
                node = intrusion_sets["edges"][0]["node"]
                intrusion_set_name_result = node["name"]
                aliases = node.get("aliases", [])
                relationships = node.get("stixCoreRelationships", {}).get("edges", [])
                all_relationships.extend(relationships)
    else:
        print("查詢失敗 (Attack-Pattern/Malware):", response1.status_code)
        print(response1.text)

    # 第二次查詢：Country 和 Sector
    query2 = generate_intrusion_set_query(intrusion_set_name, ["Country", "Sector"])
    response2 = requests.post(
        f"{opencti_url}/graphql",
        headers={
            "Authorization": f"Bearer {opencti_token}",
            "Content-Type": "application/json",
        },
        json={"query": query2}
    )

    if response2.status_code == 200:
        data = response2.json()
        if "errors" in data:
            print("GraphQL 錯誤 (Country/Sector):")
            for error in data["errors"]:
                print(error["message"])
        else:
            intrusion_sets = data.get("data", {}).get("intrusionSets")
            if intrusion_sets and intrusion_sets.get("edges"):
                node = intrusion_sets["edges"][0]["node"]
                if not intrusion_set_name_result:
                    intrusion_set_name_result = node["name"]
                    aliases = node.get("aliases", [])
                relationships = node.get("stixCoreRelationships", {}).get("edges", [])
                all_relationships.extend(relationships)
    else:
        print("查詢失敗 (Country/Sector):", response2.status_code)
        print(response2.text)

    # 輸出結果
    if not intrusion_set_name_result:
        print("未找到符合條件的入侵集合")
        return attack_pattern_ids, malware_ids

    print("入侵集合名稱:", intrusion_set_name_result)
    print("別名:", ", ".join(aliases) or "無")
    print("相關關係:")

    # 去重關係數據，根據 entity_type 和 name/x_mitre_id
    unique_relationships = []
    seen = set()
    for rel_edge in all_relationships:
        rel_node = rel_edge["node"]
        to = rel_node.get("to", {})
        entity_type = to.get("entity_type", "未知")
        identifier = None
        if entity_type == "Attack-Pattern":
            identifier = (entity_type, to.get("x_mitre_id", "無"))
        else:
            identifier = (entity_type, to.get("name", "無"))
        if identifier not in seen:
            seen.add(identifier)
            unique_relationships.append(rel_edge)

    # 檢查是否無關係數據
    if not unique_relationships:
        print("  無相關關係")
        print("=" * 40)
        return attack_pattern_ids, malware_ids

    # 輸出去重後的關係
    for rel_edge in unique_relationships:
        rel_node = rel_edge["node"]
        to = rel_node.get("to", {})
        entity_type = to.get("entity_type", "未知")
        print(f"  資訊類別: {entity_type}")
        if entity_type == "Attack-Pattern":
            mitre_id = to.get('x_mitre_id', '無')
            attack_pattern_name = get_attack_pattern_name(mitre_id)
            print(f"  MITRE ID: {mitre_id}")
            print(f"  攻擊手法名稱: {attack_pattern_name}")
            attack_pattern_ids.append(to.get("id"))
        elif entity_type == "Malware":
            print(f"  惡意軟體: {to.get('name', '無')}")
            malware_ids.append(to.get("id"))
        elif entity_type == "Country":
            print(f"  受害國家: {to.get('name', '無')}")
        elif entity_type == "Sector":
            print(f"  受害產業: {to.get('name', '無')}")
        else:
            print(f"  其他實體: {to.get('name', '無')}")
        print("-" * 20)
    print("=" * 40)

    return attack_pattern_ids, malware_ids

def generate_attack_pattern_query(attack_pattern_id, direction="to"):
    """
    生成查詢指定攻擊手法的 GraphQL 查詢字符串，使用 rf 前綴。

    Args:
        attack_pattern_id (str): 要查詢的 Attack-Pattern 的 ID。
        direction (str): 查詢方向，"to"（查詢 Attack-Pattern 指向的實體）或 "from"（查詢指向 Attack-Pattern 的實體）。

    Returns:
        str: 格式化後的 GraphQL 查詢字符串。
    """
    safe_id = attack_pattern_id.replace('"', '\\"')
    types_field = "toTypes" if direction == "to" else "fromTypes"
    target_field = "to" if direction == "to" else "from"
    query = rf"""
    query AttackPattern {{
      attackPattern(
        id: "{safe_id}"
      ) {{
        id
        x_mitre_id
        name
        description
        stixCoreRelationships(
          first: 20
          {types_field}: ["Intrusion-Set", "Malware", "Tool", "Vulnerability"]
        ) {{
          edges {{
            node {{
              id
              relationship_type
              {target_field} {{
                ... on IntrusionSet {{
                  entity_type
                  name
                }}
                ... on Malware {{
                  entity_type
                  name
                }}
                ... on Tool {{
                  entity_type
                  name
                }}
                ... on Vulnerability {{
                  entity_type
                  name
                }}
              }}
            }}
          }}
        }}
      }}
    }}
    """
    return query

def query_AttackPattern(attack_pattern_id, opencti_url, opencti_token):
    """
    查詢 OpenCTI 的 Attack-Pattern 並處理回應，同時查詢 to 和 from 方向，分別顯示去重後的關係，只有兩者都無數據時輸出 "無相關關係"。

    Args:
        attack_pattern_id (str): 要查詢的 Attack-Pattern 的 ID。
        opencti_url (str): OpenCTI 的 GraphQL API 端點。
        opencti_token (str): OpenCTI 的認證令牌。
    """
    # 儲存 to 和 from 方向的查詢結果
    to_relationships = []
    from_relationships = []
    attack_pattern_name = None
    attack_pattern_description = None
    attack_pattern_mitre_id = None

    # 查詢 to 方向
    query_to = generate_attack_pattern_query(attack_pattern_id, direction="to")
    response_to = requests.post(
        f"{opencti_url}/graphql",
        headers={
            "Authorization": f"Bearer {opencti_token}",
            "Content-Type": "application/json",
        },
        json={"query": query_to}
    )

    if response_to.status_code == 200:
        data = response_to.json()
        if "errors" in data:
            print("GraphQL 錯誤 (to):")
            for error in data["errors"]:
                print(error["message"])
        else:
            attack_pattern = data.get("data", {}).get("attackPattern")
            if attack_pattern:
                attack_pattern_name = attack_pattern["name"]
                attack_pattern_description = attack_pattern.get("description", "無")
                attack_pattern_mitre_id = attack_pattern.get("x_mitre_id", "無")
                to_relationships = attack_pattern.get("stixCoreRelationships", {}).get("edges", [])
            else:
                print("未找到符合條件的攻擊手法 (to)")
    else:
        print("查詢失敗 (to):", response_to.status_code)
        print(response_to.text)

    # 查詢 from 方向
    query_from = generate_attack_pattern_query(attack_pattern_id, direction="from")
    response_from = requests.post(
        f"{opencti_url}/graphql",
        headers={
            "Authorization": f"Bearer {opencti_token}",
            "Content-Type": "application/json",
        },
        json={"query": query_from}
    )

    if response_from.status_code == 200:
        data = response_from.json()
        if "errors" in data:
            print("GraphQL 錯誤 (from):")
            for error in data["errors"]:
                print(error["message"])
        else:
            attack_pattern = data.get("data", {}).get("attackPattern")
            if attack_pattern:
                if not attack_pattern_name:  # 如果 to 查詢未設置名稱
                    attack_pattern_name = attack_pattern["name"]
                    attack_pattern_description = attack_pattern.get("description", "無")
                    attack_pattern_mitre_id = attack_pattern.get("x_mitre_id", "無")
                from_relationships = attack_pattern.get("stixCoreRelationships", {}).get("edges", [])
            else:
                print("未找到符合條件的攻擊手法 (from)")
    else:
        print("查詢失敗 (from):", response_from.status_code)
        print(response_from.text)

    # 輸出結果
    if not attack_pattern_name:
        print("未找到攻擊手法")
        return

    print("MITRE ID:", attack_pattern_mitre_id)
    print("攻擊手法名稱:", get_attack_pattern_name(attack_pattern_mitre_id))
    print("描述:", attack_pattern_description)
    print("相關關係:")

    # 檢查是否兩個方向都無數據
    if not to_relationships and not from_relationships:
        print("  無相關關係")
        print("=" * 40)
        return

    # 去重關係數據，根據 entity_type 和 name
    def deduplicate_relationships(relationships, direction):
        unique_relationships = []
        seen = set()
        for rel_edge in relationships:
            rel_node = rel_edge["node"]
            target = rel_node.get("to" if direction == "to" else "from", {})
            entity_type = target.get("entity_type", "未知")
            name = target.get("name", "無")
            identifier = (entity_type, name)
            if identifier not in seen:
                seen.add(identifier)
                unique_relationships.append(rel_edge)
        return unique_relationships

    # 去重 to 和 from 的關係
    unique_to_relationships = deduplicate_relationships(to_relationships, "to")
    unique_from_relationships = deduplicate_relationships(from_relationships, "from")

    # 輸出 to 方向的關係
    if unique_to_relationships:
        for rel_edge in unique_to_relationships:
            rel_node = rel_edge["node"]
            target = rel_node.get("to", {})
            entity_type = target.get("entity_type", "未知")
            print(f"    資訊類別: {entity_type}")
            if entity_type == "Intrusion-Set":
                print(f"    入侵集合: {target.get('name', '無')}")
            elif entity_type == "Malware":
                print(f"    惡意軟體: {target.get('name', '無')}")
            elif entity_type == "Tool":
                print(f"    工具: {target.get('name', '無')}")
            elif entity_type == "Vulnerability":
                print(f"    漏洞: {target.get('name', '無')}")
            print("    " + "-" * 20)

    # 輸出 from 方向的關係
    if unique_from_relationships:
        for rel_edge in unique_from_relationships:
            rel_node = rel_edge["node"]
            target = rel_node.get("from", {})
            entity_type = target.get("entity_type", "未知")
            print(f"    資訊類別: {entity_type}")
            if entity_type == "Intrusion-Set":
                print(f"    入侵集合: {target.get('name', '無')}")
            elif entity_type == "Malware":
                print(f"    惡意軟體: {target.get('name', '無')}")
            elif entity_type == "Tool":
                print(f"    工具: {target.get('name', '無')}")
            elif entity_type == "Vulnerability":
                print(f"    漏洞: {target.get('name', '無')}")
            print("    " + "-" * 20)
    print("=" * 40)

def generate_malware_query(malware_id, direction="to"):
    """
    生成查詢指定惡意軟體的 GraphQL 查詢字符串，使用 rf 前綴。

    Args:
        malware_id (str): 要查詢的 Malware 的 ID。
        direction (str): 查詢方向，"to"（查詢 Malware 指向的實體）或 "from"（查詢指向 Malware 的實體）。

    Returns:
        str: 格式化後的 GraphQL 查詢字符串。
    """
    safe_id = malware_id.replace('"', '\\"')
    types_field = "toTypes" if direction == "to" else "fromTypes"
    target_field = "to" if direction == "to" else "from"
    query = rf"""
    query Malware {{
      malware(
        id: "{safe_id}"
      ) {{
        id
        name
        description
        stixCoreRelationships(
          first: 20
          {types_field}: ["Intrusion-Set", "Attack-Pattern", "Tool", "Vulnerability"]
        ) {{
          edges {{
            node {{
              id
              relationship_type
              {target_field} {{
                ... on IntrusionSet {{
                  entity_type
                  name
                }}
                ... on AttackPattern {{
                  entity_type
                  x_mitre_id
                  name
                }}
                ... on Tool {{
                  entity_type
                  name
                }}
                ... on Vulnerability {{
                  entity_type
                  name
                }}
              }}
            }}
          }}
        }}
      }}
    }}
    """
    return query

def query_Malware(malware_id, opencti_url, opencti_token):
    """
    查詢 OpenCTI 的 Malware 並處理回應，同時查詢 to 和 from 方向，只有兩者都無數據時輸出 "無相關關係"。

    Args:
        malware_id (str): 要查詢的 Malware 的 ID。
        opencti_url (str): OpenCTI 的 GraphQL API 端點。
        opencti_token (str): OpenCTI 的認證令牌。
    """
    # 儲存 to 和 from 方向的查詢結果
    to_relationships = []
    from_relationships = []
    malware_name = None
    malware_description = None

    # 查詢 to 方向
    query_to = generate_malware_query(malware_id, direction="to")
    response_to = requests.post(
        f"{opencti_url}/graphql",
        headers={
            "Authorization": f"Bearer {opencti_token}",
            "Content-Type": "application/json",
        },
        json={"query": query_to}
    )

    if response_to.status_code == 200:
        data = response_to.json()
        if "errors" in data:
            print("GraphQL 錯誤 (to):")
            for error in data["errors"]:
                print(error["message"])
        else:
            malware = data.get("data", {}).get("malware")
            if malware:
                malware_name = malware["name"]
                malware_description = malware.get("description", "無")
                to_relationships = malware.get("stixCoreRelationships", {}).get("edges", [])
            else:
                print("未找到符合條件的惡意軟體 (to)")
    else:
        print("查詢失敗 (to):", response_to.status_code)
        print(response_to.text)

    # 查詢 from 方向
    query_from = generate_malware_query(malware_id, direction="from")
    response_from = requests.post(
        f"{opencti_url}/graphql",
        headers={
            "Authorization": f"Bearer {opencti_token}",
            "Content-Type": "application/json",
        },
        json={"query": query_from}
    )

    if response_from.status_code == 200:
        data = response_from.json()
        if "errors" in data:
            print("GraphQL 錯誤 (from):")
            for error in data["errors"]:
                print(error["message"])
        else:
            malware = data.get("data", {}).get("malware")
            if malware:
                if not malware_name:  # 如果 to 查詢未設置名稱
                    malware_name = malware["name"]
                    malware_description = malware.get("description", "無")
                from_relationships = malware.get("stixCoreRelationships", {}).get("edges", [])
            else:
                print("未找到符合條件的惡意軟體 (from)")
    else:
        print("查詢失敗 (from):", response_from.status_code)
        print(response_from.text)

    # 輸出結果
    if not malware_name:
        print("未找到惡意軟體")
        return

    print("惡意軟體名稱:", malware_name)
    print("描述:", malware_description)
    print("相關關係:")

    # 檢查是否兩個方向都無數據
    if not to_relationships and not from_relationships:
        print("惡意軟體名稱:", malware_name)
        print("描述:", malware_description)
        print("無相關關係")
        #print("  無相關關係")
        print("=" * 40)
        return
    # else:
    #     print("惡意軟體名稱:", malware_name)
    #     print("描述:", malware_description)
    #     print("相關關係:")

    # 輸出 to 方向的關係
    if to_relationships:
        # print("  方向: to")
        for rel_edge in to_relationships:
            rel_node = rel_edge["node"]
            target = rel_node.get("to", {})
            entity_type = target.get("entity_type", "未知")
            print(f"    資訊類別: {entity_type}")
            if entity_type == "Intrusion-Set":
                print(f"    入侵集合: {target.get('name', '無')}")
            elif entity_type == "Attack-Pattern":
                print(f"    MITRE ID: {target.get('x_mitre_id', '無')}")
                attack_pattern_name = get_attack_pattern_name(target.get("x_mitre_id"))
                print(f"    攻擊手法: {attack_pattern_name}")
            elif entity_type == "Tool":
                print(f"    工具: {target.get('name', '無')}")
            elif entity_type == "Vulnerability":
                print(f"    漏洞: {target.get('name', '無')}")
            print("    " + "-" * 20)
    # else:
    #     print("  方向: to")
    #     print("    無相關關係")
    # print("-" * 40)

    # 輸出 from 方向的關係
    if from_relationships:
        # print("  方向: from")
        for rel_edge in from_relationships:
            rel_node = rel_edge["node"]
            target = rel_node.get("from", {})
            entity_type = target.get("entity_type", "未知")
            print(f"    資訊類別: {entity_type}")
            if entity_type == "Intrusion-Set":
                print(f"    入侵集合: {target.get('name', '無')}")
            elif entity_type == "Attack-Pattern":
                print(f"    MITRE ID: {target.get('x_mitre_id', '無')}")
                attack_pattern_name = get_attack_pattern_name(target.get("x_mitre_id"))
                print(f"    攻擊手法: {attack_pattern_name}")
            elif entity_type == "Tool":
                print(f"    工具: {target.get('name', '無')}")
            elif entity_type == "Vulnerability":
                print(f"    漏洞: {target.get('name', '無')}")
            print("    " + "-" * 20)
    # else:
    # #     print("  方向: from")
    #      print("    無相關關係")
    print("=" * 40)

if __name__ == "__main__":
    # 替換為你的 OpenCTI URL 和 Token
    OPENCTI_URL = "http://192.168.32.149:8080"
    OPENCTI_TOKEN = "88c3b1cf-101d-4a28-95ca-07abbf794bc3"

    # 步驟 1: 查詢 IntrusionSet，獲取 Attack-Pattern 和 Malware ID
    intrusion_set="APT-C-36"
    attack_pattern_ids, malware_ids = query_IntrusionSet(intrusion_set, OPENCTI_URL, OPENCTI_TOKEN)

    # 步驟 2: 查詢 Attack-Pattern
    if attack_pattern_ids:
        for ap_id in attack_pattern_ids[:]:  # 遍歷攻擊手法
            print("\n查詢 Attack-Pattern :")
            query_AttackPattern(ap_id, OPENCTI_URL, OPENCTI_TOKEN)


    # 步驟 3: 查詢 Malware
    if malware_ids:
        for m_id in malware_ids[:]:  #遍歷惡意軟體
            print("\n查詢 Malware :")
            query_Malware(m_id, OPENCTI_URL, OPENCTI_TOKEN)
