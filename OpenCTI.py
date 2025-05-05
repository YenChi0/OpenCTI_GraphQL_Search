import requests
import json
import io
from contextlib import redirect_stdout
import uuid

# 載入 MITRE ATT&CK JSON 檔案
try:
    with open('enterprise-attack.json', 'r', encoding='utf-8') as file:
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
              key: ["aliases"]  
              values: ["{safe_name}"]
              operator: eq
              mode: and
            }},
            {{
              key: ["name"]  
              values: ["{safe_name}"]
              operator: eq
              mode: and
            }}
          ]
          filterGroups: []
        }}
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
    查詢 OpenCTI 的 IntrusionSet，執行兩次查詢（Attack-Pattern/Malware 和 Country/Sector），
    合併並去重顯示關係，返回所有匹配入侵集合的 Attack-Pattern 和 Malware 的 ID 列表。

    Args:
        intrusion_set_name (str): 要查詢的攻擊組織名稱或別名。
        opencti_url (str): OpenCTI 的 GraphQL API 端點。
        opencti_token (str): OpenCTI 的認證令牌。

    Returns:
        list: 包含每個入侵集合的資料字典列表，每個字典包含 name, aliases, attack_pattern_ids, malware_ids, relationships 和 match_type。
    """
    intrusion_sets_data = []

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

    if response1.status_code == 200:
        data = response1.json()
        if "errors" in data:
            print("GraphQL 錯誤 (Attack-Pattern/Malware):")
            for error in data["errors"]:
                print(error["message"])
        else:
            intrusion_sets = data.get("data", {}).get("intrusionSets", {})
            edges = intrusion_sets.get("edges", [])
            for edge in edges:
                node = edge["node"]
                # 判斷匹配類型
                match_type = "name" if node["name"] == intrusion_set_name else "aliases"
                intrusion_set_data = {
                    "name": node["name"],
                    "aliases": node.get("aliases", []) or [],
                    "attack_pattern_ids": [],
                    "malware_ids": [],
                    "relationships": [],
                    "match_type": match_type
                }
                relationships = node.get("stixCoreRelationships", {}).get("edges", [])
                intrusion_set_data["relationships"].extend(relationships)
                intrusion_sets_data.append(intrusion_set_data)
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
            intrusion_sets = data.get("data", {}).get("intrusionSets", {})
            edges = intrusion_sets.get("edges", [])
            for edge in edges:
                node = edge["node"]
                # 檢查是否已有此入侵集合
                existing = next((item for item in intrusion_sets_data if item["name"] == node["name"]), None)
                if existing:
                    relationships = node.get("stixCoreRelationships", {}).get("edges", [])
                    existing["relationships"].extend(relationships)
                else:
                    match_type = "name" if node["name"] == intrusion_set_name else "aliases"
                    intrusion_set_data = {
                        "name": node["name"],
                        "aliases": node.get("aliases", []) or [],
                        "attack_pattern_ids": [],
                        "malware_ids": [],
                        "relationships": node.get("stixCoreRelationships", {}).get("edges", []),
                        "match_type": match_type
                    }
                    intrusion_sets_data.append(intrusion_set_data)
    else:
        print("查詢失敗 (Country/Sector):", response2.status_code)
        print(response2.text)

    # 處理並輸出每個入侵集合
    for intrusion_set_data in intrusion_sets_data:
        name = intrusion_set_data["name"]
        aliases = intrusion_set_data["aliases"]
        all_relationships = intrusion_set_data["relationships"]
        match_type = intrusion_set_data["match_type"]

        print("入侵集合名稱:", name)
        print("匹配類型:", "名稱匹配" if match_type == "name" else "別名匹配")
        print("別名:", ", ".join(aliases) if aliases else "無")
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
            continue

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
                intrusion_set_data["attack_pattern_ids"].append(to.get("id"))
            elif entity_type == "Malware":
                print(f"  惡意軟體: {to.get('name', '無')}")
                intrusion_set_data["malware_ids"].append(to.get("id"))
            elif entity_type == "Country":
                print(f"  受害國家: {to.get('name', '無')}")
            elif entity_type == "Sector":
                print(f"  受害產業: {to.get('name', '無')}")
            else:
                print(f"  其他實體: {to.get('name', '無')}")
            print("-" * 20)
        print("=" * 40)

    return intrusion_sets_data

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
        print("查詢失敗 (from):", response_to.status_code)
        print(response_to.text)

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
        print("查詢失敗 (from):", response_to.status_code)
        print(response_to.text)

    # 輸出結果
    if not malware_name:
        print("未找到惡意軟體")
        return

    print("惡意軟體名稱:", malware_name)
    print("描述:", malware_description)
    print("相關關係:")

    # 檢查是否兩個方向都無數據
    if not to_relationships and not from_relationships:
        print("  無相關關係")
        print("=" * 40)
        return

    # 輸出 to 方向的關係
    if to_relationships:
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

    # 輸出 from 方向的關係
    if from_relationships:
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
    print("=" * 40)

if __name__ == "__main__":
    # 替換為你的 OpenCTI URL 和 Token
    OPENCTI_URL = "http://192.168.32.149:8080"
    OPENCTI_TOKEN = "88c3b1cf-101d-4a28-95ca-07abbf794bc3"

    # 讀取資安事件 JSON 檔案
    try:
        with open('my_nerresult.json', 'r', encoding='utf-8') as file:
            security_incidents = json.load(file)
        # 驗證 security_incidents 是否為列表
        if not isinstance(security_incidents, list):
            print("錯誤: my_nerresult.json 內容必須為 JSON 陣列")
            security_incidents = []
    except FileNotFoundError:
        print("錯誤: 找不到 my_nerresult.json 檔案")
        security_incidents = []
    except json.JSONDecodeError:
        print("錯誤: my_nerresult.json 檔案格式無效")
        security_incidents = []

    # 提取所有攻擊者名稱，保留順序且不去重
    attackers = []
    for incident in security_incidents:
        if incident.get("Attacker"):
            attackers.extend(incident["Attacker"])
    print("攻擊者列表:", attackers)

    # 準備 JSON 輸出結構
    output_data = {
        "intrusion_sets": []
    }

    # 對每個攻擊者執行查詢，保留順序
    for idx, attacker in enumerate(attackers, 1):
        print(f"\n查詢攻擊者: {attacker} (第 {idx} 次)")
        # 查詢 IntrusionSet，獲取所有匹配的入侵集合
        print_buffer = io.StringIO()
        with redirect_stdout(print_buffer):
            intrusion_sets_data = query_IntrusionSet(attacker, OPENCTI_URL, OPENCTI_TOKEN)
        intrusion_set_output = print_buffer.getvalue()
        print(intrusion_set_output)  # 仍然在控制台顯示

        # 如果未找到任何入侵集合，記錄空結果
        if not intrusion_sets_data:
            print("未找到符合條件的入侵集合")
            intrusion_set_data = {
                "name": None,
                "aliases": [],
                "relationships": [],
                "attack_patterns": [],
                "malwares": [],
                # "match_type": None,
                # "query_attacker": attacker,
                # "query_index": idx
            }
            output_data["intrusion_sets"].append(intrusion_set_data)
            continue

        # 處理每個入侵集合
        for intrusion_set_data in intrusion_sets_data:
            attack_pattern_ids = intrusion_set_data["attack_pattern_ids"]
            malware_ids = intrusion_set_data["malware_ids"]
            match_type = intrusion_set_data["match_type"]

            # 解析 IntrusionSet 輸出並儲存到 JSON
            current_relationship = None
            intrusion_set_json = {
                "name": intrusion_set_data["name"],
                "aliases": intrusion_set_data["aliases"],
                "relationships": [],
                "attack_patterns": [],
                "malwares": [],
                "match_type": "name" if match_type == "name" else "aliases",
                "query_attacker": attacker,
                "query_index": idx
            }
            for line in intrusion_set_output.splitlines():
                line = line.rstrip()
                if line.startswith("入侵集合名稱:"):
                    intrusion_set_json["name"] = line.split(":", 1)[1].strip()
                elif line.startswith("匹配類型:"):
                    intrusion_set_json["match_type"] = line.split(":", 1)[1].strip()
                    intrusion_set_json["match_type"] = "name" if intrusion_set_json["match_type"] == "名稱匹配" else "aliases"
                elif line.startswith("別名:"):
                    aliases = line.split(":", 1)[1].strip()
                    intrusion_set_json["aliases"] = [a.strip() for a in aliases.split(",")] if aliases != "無" else []
                elif line.startswith("  資訊類別:"):
                    if current_relationship:
                        intrusion_set_json["relationships"].append(current_relationship)
                    current_relationship = {"entity_type": line.split(":", 1)[1].strip()}
                elif current_relationship and line.startswith("  MITRE ID:"):
                    current_relationship["mitre_id"] = line.split(":", 1)[1].strip()
                elif current_relationship and line.startswith("  攻擊手法名稱:"):
                    current_relationship["attack_pattern_name"] = line.split(":", 1)[1].strip()
                elif current_relationship and line.startswith("  惡意軟體:"):
                    current_relationship["malware_name"] = line.split(":", 1)[1].strip()
                elif current_relationship and line.startswith("  受害國家:"):
                    current_relationship["country"] = line.split(":", 1)[1].strip()
                elif current_relationship and line.startswith("  受害產業:"):
                    current_relationship["sector"] = line.split(":", 1)[1].strip()
                elif current_relationship and line.startswith("  其他實體:"):
                    current_relationship["other_entity"] = line.split(":", 1)[1].strip()
            if current_relationship:
                intrusion_set_json["relationships"].append(current_relationship)

            # 步驟 2: 查詢 Attack-Pattern
            if attack_pattern_ids:
                for ap_id in attack_pattern_ids[:]:
                    print_buffer = io.StringIO()
                    with redirect_stdout(print_buffer):
                        print("\n查詢 Attack-Pattern :")
                        query_AttackPattern(ap_id, OPENCTI_URL, OPENCTI_TOKEN)
                    attack_pattern_output = print_buffer.getvalue()
                    print(attack_pattern_output)  # 仍然在控制台顯示

                    # 解析 AttackPattern 輸出
                    attack_pattern_data = {
                        "mitre_id": None,
                        "name": None,
                        "description": None,
                        "relationships": []
                    }
                    current_relationship = None
                    for line in attack_pattern_output.splitlines():
                        line = line.rstrip()
                        if line.startswith("MITRE ID:"):
                            attack_pattern_data["mitre_id"] = line.split(":", 1)[1].strip()
                        elif line.startswith("攻擊手法名稱:"):
                            attack_pattern_data["name"] = line.split(":", 1)[1].strip()
                        elif line.startswith("描述:"):
                            attack_pattern_data["description"] = line.split(":", 1)[1].strip()
                        elif line.startswith("    資訊類別:"):
                            if current_relationship:
                                attack_pattern_data["relationships"].append(current_relationship)
                            current_relationship = {"entity_type": line.split(":", 1)[1].strip()}
                        elif current_relationship and line.startswith("    入侵集合:"):
                            current_relationship["intrusion_set"] = line.split(":", 1)[1].strip()
                        elif current_relationship and line.startswith("    惡意軟體:"):
                            current_relationship["malware"] = line.split(":", 1)[1].strip()
                        elif current_relationship and line.startswith("    工具:"):
                            current_relationship["tool"] = line.split(":", 1)[1].strip()
                        elif current_relationship and line.startswith("    漏洞:"):
                            current_relationship["vulnerability"] = line.split(":", 1)[1].strip()
                    if current_relationship:
                        attack_pattern_data["relationships"].append(current_relationship)
                    intrusion_set_json["attack_patterns"].append(attack_pattern_data)

            # 步驟 3: 查詢 Malware
            if malware_ids:
                for m_id in malware_ids[:]:
                    print_buffer = io.StringIO()
                    with redirect_stdout(print_buffer):
                        print("\n查詢 Malware :")
                        query_Malware(m_id, OPENCTI_URL, OPENCTI_TOKEN)
                    malware_output = print_buffer.getvalue()
                    print(malware_output)  # 仍然在控制台顯示

                    # 解析 Malware 輸出
                    malware_data = {
                        "name": None,
                        "description": None,
                        "relationships": []
                    }
                    current_relationship = None
                    for line in attack_pattern_output.splitlines():
                        line = line.rstrip()
                        if line.startswith("惡意軟體名稱:"):
                            malware_data["name"] = line.split(":", 1)[1].strip()
                        elif line.startswith("描述:"):
                            malware_data["description"] = line.split(":", 1)[1].strip()
                        elif line.startswith("    資訊類別:"):
                            if current_relationship:
                                malware_data["relationships"].append(current_relationship)
                            current_relationship = {"entity_type": line.split(":", 1)[1].strip()}
                        elif current_relationship and line.startswith("    入侵集合:"):
                            current_relationship["intrusion_set"] = line.split(":", 1)[1].strip()
                        elif current_relationship and line.startswith("    MITRE ID:"):
                            current_relationship["mitre_id"] = line.split(":", 1)[1].strip()
                        elif current_relationship and line.startswith("    攻擊手法:"):
                            current_relationship["attack_pattern"] = line.split(":", 1)[1].strip()
                        elif current_relationship and line.startswith("    工具:"):
                            current_relationship["tool"] = line.split(":", 1)[1].strip()
                        elif current_relationship and line.startswith("    漏洞:"):
                            current_relationship["vulnerability"] = line.split(":", 1)[1].strip()
                    if current_relationship:
                        malware_data["relationships"].append(current_relationship)
                    intrusion_set_json["malwares"].append(malware_data)

            # 將單個 intrusion_set 數據添加到 output_data
            output_data["intrusion_sets"].append(intrusion_set_json)

    # 保存到 opencti.json
    try:
        with open('opencti.json', 'w', encoding='utf-8') as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        print("結果已保存到 opencti.json")
    except Exception as e:
        print(f"保存 opencti.json 失敗: {str(e)}")