package aws

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/hashcode"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
)

var dataSourceAwsIamPolicyDocumentVarReplacer = strings.NewReplacer("&{", "${")

func dataSourceAwsEcsTaskDefinitionDocument() *schema.Resource {
	setOfString := &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
	}

	return &schema.Resource{
		Read: dataSourceAwsEcsTaskDefinitionDocumentRead,

		Schema: map[string]*schema.Schema{
			"container_definition": {
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"image": {
							Type:     schema.TypeString,
							Required: true,
						},
						"memory": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"memory_reservation": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"port_mappings": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"container_port": {
										Type:     schema.TypeInt,
										Optional: true,
									},
									"host_port": {
										Type:     schema.TypeInt,
										Optional: true,
									},
									"protocol": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
						"health_check": {
							Type:     schema.TypeMap,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"command": {
										Type:     schema.TypeList,
										Required: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"interval": {
										Type:     schema.TypeInt,
										Optional: true,
									},
									"timeout": {
										Type:     schema.TypeInt,
										Optional: true,
									},
									"retries": {
										Type:     schema.TypeInt,
										Optional: true,
									},
									"start_period": {
										Type:     schema.TypeInt,
										Optional: true,
									},
								},
							},
						},
						"cpu": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"gpu": {
							Type:     schema.TypeMap,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"type": {
										Type:         schema.TypeString,
										Required:     true,
										Default:      "GPU",
										ValidateFunc: validation.StringInSlice([]string{"GPU", "InferenceAccelerator"}, false),
									},
									"value": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},
						"essential": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"entry_point": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"command": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"working_directory": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"environment": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Required: true,
									},
									"value": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},
						"secrets": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Required: true,
									},
									"value_from": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},
						"disable_networking": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"links": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"hostname": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"dns_servers": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"dns_search_domains": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"extra_hosts": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"hostname": {
										Type:     schema.TypeString,
										Required: true,
									},
									"ip_address": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},
						"readonly_root_filesystem": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"mount_points": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"source_volume": {
										Type:     schema.TypeString,
										Required: true,
									},
									"container_path": {
										Type:     schema.TypeString,
										Required: true,
									},
									"read_only": {
										Type:     schema.TypeBool,
										Optional: true,
									},
								},
							},
						},
						"volumes_from": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"source_container": {
										Type:     schema.TypeString,
										Required: true,
									},
									"read_only": {
										Type:     schema.TypeBool,
										Optional: true,
									},
								},
							},
						},
						"log_configuration": {
							Type:     schema.TypeMap,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"log_driver": {
										Type:     schema.TypeString,
										Required: true,
									},
									"options": {
										Type:     schema.TypeMap,
										Optional: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"secret_options": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"name": {
													Type:     schema.TypeString,
													Required: true,
												},
												"value_from": {
													Type:     schema.TypeString,
													Required: true,
												},
											},
										},
									},
								},
							},
						},
						"security": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"user": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"docker_security_options": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"ulimits": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"name": {
										Type:     schema.TypeString,
										Required: true,
									},
									"hard_limit": {
										Type:     schema.TypeInt,
										Required: true,
									},
									"soft_limit": {
										Type:     schema.TypeInt,
										Required: true,
									},
								},
							},
						},
						"docker_labels": {
							Type:     schema.TypeMap,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"depends_on": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"container_name": {
										Type:     schema.TypeString,
										Required: true,
									},
									"condition": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},
						"start_timeout": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"stop_timeout": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"interactive": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"pseudo_terminal": {
							Type:     schema.TypeBool,
							Optional: true,
						},
					},
				},
			},
		},
	}
}

func dataSourceAwsEcsTaskDefinitionDocumentRead(d *schema.ResourceData, meta interface{}) error {
	mergedDoc := &IAMPolicyDoc{}

	// populate mergedDoc directly with any source_json
	if sourceJSON, hasSourceJSON := d.GetOk("source_json"); hasSourceJSON {
		if err := json.Unmarshal([]byte(sourceJSON.(string)), mergedDoc); err != nil {
			return err
		}
	}

	// process the current document
	doc := &IAMPolicyDoc{
		Version: d.Get("version").(string),
	}

	if policyID, hasPolicyID := d.GetOk("policy_id"); hasPolicyID {
		doc.Id = policyID.(string)
	}

	if cfgStmts, hasCfgStmts := d.GetOk("statement"); hasCfgStmts {
		var cfgStmtIntf = cfgStmts.([]interface{})
		stmts := make([]*IAMPolicyStatement, len(cfgStmtIntf))
		sidMap := make(map[string]struct{})

		for i, stmtI := range cfgStmtIntf {
			cfgStmt := stmtI.(map[string]interface{})
			stmt := &IAMPolicyStatement{
				Effect: cfgStmt["effect"].(string),
			}

			if sid, ok := cfgStmt["sid"]; ok {
				if _, ok := sidMap[sid.(string)]; ok {
					return fmt.Errorf("Found duplicate sid (%s). Either remove the sid or ensure the sid is unique across all statements", sid.(string))
				}
				stmt.Sid = sid.(string)
				if len(stmt.Sid) > 0 {
					sidMap[stmt.Sid] = struct{}{}
				}
			}

			if actions := cfgStmt["actions"].(*schema.Set).List(); len(actions) > 0 {
				stmt.Actions = iamPolicyDecodeConfigStringList(actions)
			}
			if actions := cfgStmt["not_actions"].(*schema.Set).List(); len(actions) > 0 {
				stmt.NotActions = iamPolicyDecodeConfigStringList(actions)
			}

			if resources := cfgStmt["resources"].(*schema.Set).List(); len(resources) > 0 {
				var err error
				stmt.Resources, err = dataSourceAwsIamPolicyDocumentReplaceVarsInList(
					iamPolicyDecodeConfigStringList(resources), doc.Version,
				)
				if err != nil {
					return fmt.Errorf("error reading resources: %s", err)
				}
			}
			if notResources := cfgStmt["not_resources"].(*schema.Set).List(); len(notResources) > 0 {
				var err error
				stmt.NotResources, err = dataSourceAwsIamPolicyDocumentReplaceVarsInList(
					iamPolicyDecodeConfigStringList(notResources), doc.Version,
				)
				if err != nil {
					return fmt.Errorf("error reading not_resources: %s", err)
				}
			}

			if principals := cfgStmt["principals"].(*schema.Set).List(); len(principals) > 0 {
				var err error
				stmt.Principals, err = dataSourceAwsIamPolicyDocumentMakePrincipals(principals, doc.Version)
				if err != nil {
					return fmt.Errorf("error reading principals: %s", err)
				}
			}

			if notPrincipals := cfgStmt["not_principals"].(*schema.Set).List(); len(notPrincipals) > 0 {
				var err error
				stmt.NotPrincipals, err = dataSourceAwsIamPolicyDocumentMakePrincipals(notPrincipals, doc.Version)
				if err != nil {
					return fmt.Errorf("error reading not_principals: %s", err)
				}
			}

			if conditions := cfgStmt["condition"].(*schema.Set).List(); len(conditions) > 0 {
				var err error
				stmt.Conditions, err = dataSourceAwsIamPolicyDocumentMakeConditions(conditions, doc.Version)
				if err != nil {
					return fmt.Errorf("error reading condition: %s", err)
				}
			}

			stmts[i] = stmt
		}

		doc.Statements = stmts

	}

	// merge our current document into mergedDoc
	mergedDoc.Merge(doc)

	// merge in override_json
	if overrideJSON, hasOverrideJSON := d.GetOk("override_json"); hasOverrideJSON {
		overrideDoc := &IAMPolicyDoc{}
		if err := json.Unmarshal([]byte(overrideJSON.(string)), overrideDoc); err != nil {
			return err
		}

		mergedDoc.Merge(overrideDoc)
	}

	jsonDoc, err := json.MarshalIndent(mergedDoc, "", "  ")
	if err != nil {
		// should never happen if the above code is correct
		return err
	}
	jsonString := string(jsonDoc)

	d.Set("json", jsonString)
	d.SetId(strconv.Itoa(hashcode.String(jsonString)))

	return nil
}

func dataSourceAwsIamPolicyDocumentReplaceVarsInList(in interface{}, version string) (interface{}, error) {
	switch v := in.(type) {
	case string:
		if version == "2008-10-17" && strings.Contains(v, "&{") {
			return nil, fmt.Errorf("found &{ sequence in (%s), which is not supported in document version 2008-10-17", v)
		}
		return dataSourceAwsIamPolicyDocumentVarReplacer.Replace(v), nil
	case []string:
		out := make([]string, len(v))
		for i, item := range v {
			if version == "2008-10-17" && strings.Contains(item, "&{") {
				return nil, fmt.Errorf("found &{ sequence in (%s), which is not supported in document version 2008-10-17", item)
			}
			out[i] = dataSourceAwsIamPolicyDocumentVarReplacer.Replace(item)
		}
		return out, nil
	default:
		panic("dataSourceAwsIamPolicyDocumentReplaceVarsInList: input not string nor []string")
	}
}

func dataSourceAwsIamPolicyDocumentMakeConditions(in []interface{}, version string) (IAMPolicyStatementConditionSet, error) {
	out := make([]IAMPolicyStatementCondition, len(in))
	for i, itemI := range in {
		var err error
		item := itemI.(map[string]interface{})
		out[i] = IAMPolicyStatementCondition{
			Test:     item["test"].(string),
			Variable: item["variable"].(string),
		}
		out[i].Values, err = dataSourceAwsIamPolicyDocumentReplaceVarsInList(
			iamPolicyDecodeConfigStringList(
				item["values"].(*schema.Set).List(),
			), version,
		)
		if err != nil {
			return nil, fmt.Errorf("error reading values: %s", err)
		}
	}
	return IAMPolicyStatementConditionSet(out), nil
}

func dataSourceAwsIamPolicyDocumentMakePrincipals(in []interface{}, version string) (IAMPolicyStatementPrincipalSet, error) {
	out := make([]IAMPolicyStatementPrincipal, len(in))
	for i, itemI := range in {
		var err error
		item := itemI.(map[string]interface{})
		out[i] = IAMPolicyStatementPrincipal{
			Type: item["type"].(string),
		}
		out[i].Identifiers, err = dataSourceAwsIamPolicyDocumentReplaceVarsInList(
			iamPolicyDecodeConfigStringList(
				item["identifiers"].(*schema.Set).List(),
			), version,
		)
		if err != nil {
			return nil, fmt.Errorf("error reading identifiers: %s", err)
		}
	}
	return IAMPolicyStatementPrincipalSet(out), nil
}

func dataSourceAwsIamPolicyPrincipalSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"type": {
					Type:     schema.TypeString,
					Required: true,
				},
				"identifiers": {
					Type:     schema.TypeSet,
					Required: true,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},
			},
		},
	}
}
