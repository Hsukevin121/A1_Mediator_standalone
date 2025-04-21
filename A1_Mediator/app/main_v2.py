from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException, Path, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pathlib import Path as OsPath

import os
import json, glob
import pymysql
import requests

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "rtlab666",
    "database": "a1db"
}
XAPP_API = "http://localhost:9100"

class CreateSchema(BaseModel):
    schema_: Optional[str] = Field(alias="$schema", default="http://json-schema.org/draft-07/schema#")
    type: str = "object"
    properties: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    additionalProperties: bool = False

    @classmethod
    def validate_properties(cls, schema: "CreateSchema"):
        properties = schema.properties
        for prop_name, prop_details in properties.items():
            if "type" not in prop_details or prop_details["type"] not in ["integer", "bool"]:
                raise ValueError(f"Invalid property type for '{prop_name}'. Only 'integer' and 'bool' are allowed.")
        return schema

class PolicyTypeSchema(BaseModel):
    name: str
    description: str
    policy_type_id: int = 10000
    create_schema: CreateSchema = None

class PolicyInstanceSchema(BaseModel):
    data: Dict[str, Any]

policy_instances = {}

@app.get("/a1-p/healthcheck")
async def get_healthcheck():
    return {"status": "A1 is healthy"}

@app.get("/a1-p/policytypes", response_model=list[int])
async def get_all_policy_types():
    try:
        conn = pymysql.connect(**DB_CONFIG)
        with conn.cursor() as cursor:
            cursor.execute("SELECT DISTINCT policy_type_id FROM policy_types")
            rows = cursor.fetchall()
            return [row[0] for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error: {str(e)}")
    finally:
        if conn: conn.close()

@app.get("/a1-p/policytypes/{policy_type_id}", response_model=PolicyTypeSchema)
async def get_policy_type(policy_type_id: int = Path(...)):
    try:
        conn = pymysql.connect(**DB_CONFIG)
        with conn.cursor() as cursor:
            cursor.execute("SELECT name, description, schema_json FROM policy_types WHERE policy_type_id = %s", (policy_type_id,))
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Policy type not found")
            name, description, schema_str = row
            create_schema = CreateSchema(**json.loads(schema_str))
            return PolicyTypeSchema(name=name, description=description, policy_type_id=policy_type_id, create_schema=create_schema)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error: {str(e)}")
    finally:
        if conn: conn.close()

@app.put("/a1-p/policytypes/{policy_type_id}", response_model=PolicyTypeSchema)
async def create_policy_type(policy_type_id: int, body: PolicyTypeSchema = Body(...)):
    CreateSchema.validate_properties(body.create_schema)
    try:
        conn = pymysql.connect(**DB_CONFIG)
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1 FROM policy_types WHERE policy_type_id = %s", (policy_type_id,))
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="Policy type already exists")
            schema_json = json.dumps(body.create_schema.dict(by_alias=True))
            cursor.execute("""
                INSERT INTO policy_types (policy_type_id, name, description, schema_json)
                VALUES (%s, %s, %s, %s)
            """, (policy_type_id, body.name, body.description, schema_json))
            conn.commit()
            return body
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB insert error: {str(e)}")
    finally:
        if conn: conn.close()

@app.put("/a1-p/policytypes/{policy_type_id}/policies/{policy_instance_id}", response_model=PolicyInstanceSchema)
async def create_policy_instance(policy_type_id: int, policy_instance_id: str, body: Dict[str, Any] = Body(...)):
    try:
        conn = pymysql.connect(**DB_CONFIG)
        with conn.cursor() as cursor:
            cursor.execute("SELECT schema_json FROM policy_types WHERE policy_type_id = %s", (policy_type_id,))
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Policy type does not exist")
            schema_properties = json.loads(row[0])["properties"]
            for field_name, field_value in body.items():
                if field_name not in schema_properties:
                    raise HTTPException(status_code=400, detail=f"Field '{field_name}' is not allowed.")
                expected_type = schema_properties[field_name]["type"]
                if expected_type == "integer" and not isinstance(field_value, int):
                    raise HTTPException(status_code=400, detail=f"Field '{field_name}' must be an integer.")
                if expected_type == "bool" and not isinstance(field_value, bool):
                    raise HTTPException(status_code=400, detail=f"Field '{field_name}' must be a boolean.")
            policy_instances.setdefault(policy_type_id, {})[policy_instance_id] = {"data": body}
            cursor.execute("SELECT app_name FROM xapp_policies WHERE policy_type_id = %s AND is_active = 1", (policy_type_id,))
            xapp = cursor.fetchone()
            if xapp:
                app_name = xapp[0]
                requests.post(f"{XAPP_API}/run", json={"app_name": app_name})
            return {"data": body}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during policy execution: {str(e)}")
    finally:
        if conn: conn.close()

@app.get("/a1-p/policytypes/{policy_type_id}/policies", response_model=list[str])
async def list_policy_instances(policy_type_id: int):
    if policy_type_id not in policy_instances:
        raise HTTPException(status_code=404, detail="Policy type does not exist")
    return list(policy_instances[policy_type_id].keys())

@app.delete("/a1-p/policytypes/{policy_type_id}/policies/{policy_instance_id}")
async def delete_policy_instance(policy_type_id: int, policy_instance_id: str):
    if policy_type_id not in policy_instances or policy_instance_id not in policy_instances[policy_type_id]:
        raise HTTPException(status_code=404, detail="Policy instance not found")
    del policy_instances[policy_type_id][policy_instance_id]
    return {"detail": "Policy instance successfully deleted"}

@app.delete("/a1-p/policytypes/{policy_type_id}")
async def delete_policy_type(policy_type_id: int):
    try:
        conn = pymysql.connect(**DB_CONFIG)
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM policy_types WHERE policy_type_id = %s", (policy_type_id,))
            conn.commit()
            if policy_type_id in policy_instances:
                del policy_instances[policy_type_id]
        return {"detail": "Policy type and instances deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn: conn.close()

@app.get("/lookup/{policy_type_id}")
async def lookup_app(policy_type_id: int):
    try:
        conn = pymysql.connect(**DB_CONFIG)
        with conn.cursor() as cursor:
            cursor.execute("SELECT app_name FROM xapp_policies WHERE policy_type_id = %s AND is_active = 1", (policy_type_id,))
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="No app_name found for this policy_type_id")
            return {"app_name": row[0]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn: conn.close()

@app.post("/trigger_xapp/{policy_type_id}")
async def trigger_xapp(policy_type_id: int):
    try:
        conn = pymysql.connect(**DB_CONFIG)
        with conn.cursor() as cursor:
            cursor.execute("SELECT app_name FROM xapp_policies WHERE policy_type_id = %s AND is_active = 1", (policy_type_id,))
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="No xApp found for this policy_type_id")
            app_name = row[0]
            response = requests.post(f"{XAPP_API}/run", json={"app_name": app_name})
            return {
                "message": "xApp trigger success",
                "app_name": app_name,
                "response_code": response.status_code,
                "response": response.text
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error triggering xApp: {str(e)}")
    finally:
        if conn: conn.close()

@app.post("/stop_xapp/{policy_type_id}")
async def stop_xapp(policy_type_id: int):
    try:
        conn = pymysql.connect(**DB_CONFIG)
        with conn.cursor() as cursor:
            cursor.execute("SELECT app_name FROM xapp_policies WHERE policy_type_id = %s", (policy_type_id,))
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="No xApp for this policy_type_id")
            app_name = row[0]
            response = requests.post(f"{XAPP_API}/stop", json={"app_name": app_name})
            return {
                "message": "xApp stopped",
                "app_name": app_name,
                "response": response.text
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn: conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9000)
