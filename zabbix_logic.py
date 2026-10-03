import requests
import urllib3
import logging
import time
import random
import re
import traceback
import threading
from datetime import datetime, timedelta
from models import ZabbixAlert, SystemLog, Noticia, ClienteChamado, ClassificacaoChamado, EquipeFrase, AtlasConfig, User, ZabbixAILearning, ZabbixFilterPreset, TeamZabbixConfig, AlertBlacklist, Team
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, session, send_file, has_request_context
from flask_login import login_required, current_user
from extensions import db
from sqlalchemy import or_, and_, func, desc, exc, case, text
import pandas as pd
import zipfile
from chat_logic import search_all_alerts, gerar_resposta_llm
from sqlalchemy.orm import joinedload, load_only
from sqlalchemy.orm import load_only
from models import Procedimento
import base64
from models import AlertBlacklist
import tempfile # <--- Importante para corrigir o caminho do arquivo depois
from azure_auth import encrypt_token, decrypt_token  # 👈 IMPORTAÇÃO ADICIONADA AQUI

def _get_decrypted_zabbix_pass(pwd):
    """
    Descriptografa a senha se estiver em hash.
    Se for senha legada em texto puro (pré-migração), retorna ela mesma sem quebrar.
    """
    if not pwd:
        return ""
    try:
        return decrypt_token(pwd)
    except Exception:
        return pwd

# Bloco de compatibilidade Windows/Linux
try:
    import fcntl
except ImportError:
    # Cria uma classe "falsa" para o Windows não quebrar
    class fcntl:
        LOCK_UN = 0
        LOCK_EX = 0
        LOCK_SH = 0
        LOCK_NB = 0
        
        @staticmethod
        def flock(fd, operation):
            return # Não faz nada no Windows
import os
from collections import defaultdict, Counter
from io import BytesIO
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy import case

# Import da busca inteligente (para o Cérebro funcionar)
from chat_logic import search_all_alerts
from PIL import Image, ImageDraw, ImageFont

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuração de Log
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("AtlasZabbix")

zabbix_bp = Blueprint('zabbix', __name__)

# ==============================================================================
# CONFIGURAÇÕES ZABBIX
# ==============================================================================
import os
# NOTE (public/portfolio version): the two constants below originally pointed to
# this project's real internal Zabbix front-end and a fallback internal IP.
# Replaced with placeholder/example values — set the real ones via env vars.
ZABBIX_FRONT_URL = os.getenv("ZABBIX_FRONT_URL", "https://zabbix.example.com")
ZABBIX_FRONT_URL_FALLBACK = os.getenv("ZABBIX_FRONT_URL_FALLBACK", "http://10.0.0.10")
ZABBIX_API_URL = f"{ZABBIX_FRONT_URL}/api_jsonrpc.php"
ZABBIX_MASTER_USER = os.getenv("ZABBIX_MASTER_USER", "atlas")
ZABBIX_MASTER_PASS = os.getenv("ZABBIX_MASTER_PASS", "")

# ==============================================================================
# CONSTANTES DE RELATÓRIO EXECUTIVO
# ==============================================================================
# NOTE (public/portfolio version): the original list here held real client/host-group
# names (Zabbix host groups mapped to real client organizations). Replaced with
# generic placeholder group names — the filtering logic below is unchanged.
DEFAULT_PJ_GROUPS = [
    "CLIENTE_01", "CLIENTE_02", "CLIENTE_03", "CLIENTE_04", "CLIENTE_05", "CLIENTE_06", "CLIENTE_07", "CLIENTE_08",
    "_PROXY_INTERNO", "EMPRESA_INTERNA", "_Zabbix Proxy", "_Zabbix Server", "CLIENTE_09", "CLIENTE_10",
    "CLIENTE_11", "CLIENTE_12", "CLIENTE_12 (Portal)", "CLIENTE_13", "CLIENTE_14", "CLIENTE_15", "CLIENTE_16",
    "CLIENTE_17", "CLIENTE_18", "CLIENTE_19 (Portal)", "_VPN-INTERNA", "VPN", "CLIENTE_20",
    "VAULT - INTERNO", "CLIENTE_21", "CLIENTE_22", "CLIENTE_23", "CLIENTE_24", "GITLAB", "CLIENTE_25"
]

# Palavras-chave para classificar um alerta como "Downtime" (SLA)
DOWNTIME_KEYWORDS = ['down', 'indispon', 'inacess', 'notready', 'out of memory', '100%']
# Palavras-chave para ignorar do cálculo de downtime
IGNORE_KEYWORDS = ['proxy', 'homolog', 'dev', 'test', 'runner']


# ==============================================================================
# CACHE DE MEMÓRIA (BLINDADO VIA REDIS)
# ==============================================================================
import redis
import json

redis_db = redis.from_url('redis://redis:6379/0', decode_responses=True)

def sync_zabbix_to_db(app_context, days=7, target='all'):
    with app_context:
        try:
            from models import AlertBlacklist, AlertPriorityRule
            agora_sync = datetime.now()
            
            regras_blacklist = db.session.query(AlertBlacklist).filter(
                AlertBlacklist.is_active == True,
                or_(AlertBlacklist.expiration_date == None, AlertBlacklist.expiration_date > agora_sync)
            ).all()

            regras_prioridade = db.session.query(AlertPriorityRule).filter(AlertPriorityRule.is_active == True).all()

            preset_cache = {}
            for regra in regras_blacklist:
                if regra.team_name not in preset_cache:
                    preset_equipe = ZabbixFilterPreset.query.filter_by(equipe_dona=regra.team_name).first()
                    if preset_equipe and preset_equipe.grupos:
                        preset_cache[regra.team_name] = [g.strip() for g in preset_equipe.grupos.split(',')]
                    else:
                        preset_cache[regra.team_name] = []

            blacklist_compilada = []
            for regra in regras_blacklist:
                grupos_permitidos = preset_cache.get(regra.team_name, [])
                regra_grupos = getattr(regra, 'host_groups', None)
                lista_restr = [g.strip().lower() for g in regra_grupos.split(',') if g.strip()] if regra_grupos else []
                blacklist_compilada.append({
                    'grupos_permitidos': grupos_permitidos,
                    'lista_restr': lista_restr,
                    'trigger_pat': (regra.trigger_pattern or '').lower(),
                    'host_pat': (regra.host_pattern or '').lower()
                })

            prio_compilada = []
            for rp in regras_prioridade:
                grupos_prio = [g.strip().lower() for g in rp.host_groups.split(',') if g.strip()] if getattr(rp, 'host_groups', None) else []
                prio_compilada.append({
                    'grupos_prio': grupos_prio,
                    'trigger_pat': (rp.trigger_pattern or '').lower(),
                    'host_pat': (rp.host_pattern or '').lower()
                })

            motores = []
            config_global = AtlasConfig.query.first()
            if not config_global: config_global = AtlasConfig(auto_ack_enabled=False)
            
            raw_global = config_global.buffer_minutes
            b_mins_global = raw_global if raw_global is not None else 5
            
            motores.append({
                "id_source": "global",
                "bridge": zabbix_api, 
                "auto_ack": config_global.auto_ack_enabled,
                "sevs": config_global.auto_ack_severities.split(',') if config_global.auto_ack_severities else [],
                "groups": [g.strip() for g in config_global.auto_ack_groups.split(',')] if config_global.auto_ack_groups else [],
                "buffer_mins": b_mins_global
            })
            
            team_configs = TeamZabbixConfig.query.all()
            times_shadow = [] 
            
            for tc in team_configs:
                if not tc.zabbix_url: continue
                if tc.shadow_mode_active:
                    times_shadow.append(tc.team_name)
                    
                try:
                    requests.get(tc.zabbix_url, timeout=3, verify=False)
                except requests.exceptions.RequestException:
                    logger.warning(f"[BACKGROUND] Zabbix {tc.team_name} inatingível. Pulando sincronização.")
                    continue
                
                raw_tc = tc.buffer_minutes
                b_mins_tc = raw_tc if raw_tc is not None else 5
                
                team_bridge = ZabbixBridge(
                    front_url=tc.zabbix_url, 
                    user=tc.api_user, 
                    password=_get_decrypted_zabbix_pass(tc.api_password)
                )
                motores.append({
                    "id_source": tc.team_name,
                    "bridge": team_bridge,
                    "auto_ack": tc.auto_ack_enabled,
                    "sevs": tc.target_severities.split(',') if tc.target_severities else [],
                    "groups": [g.strip() for g in tc.whitelist_groups.split(',')] if tc.whitelist_groups else [],
                    "buffer_mins": b_mins_tc
                })

            for motor in motores:
                fonte = motor["id_source"]
                bridge = motor["bridge"]
                
                # 🌟 SEPARAÇÃO DAS ROTINAS (ROTEAMENTO POR TARGET) 🌟
                if target == 'global' and fonte != 'global':
                    continue
                if target == 'multi' and fonte == 'global':
                    continue
                
                problems = bridge.get_enriched_problems(groups=None, days=days, fetch_mon_unlimited=True, fetch_all_high_crit=True)
                
                if problems is None:
                    continue

                current_event_ids = [str(p['eventid']) for p in problems]
                
                if problems:
                    triggers_in_batch = [str(p['objectid']) for p in problems]
                    limite_janela_busca = datetime.now() - timedelta(days=days)
                    
                    db.session.query(ZabbixAlert).filter(
                        ZabbixAlert.source_zabbix == fonte,
                        ZabbixAlert.status == 'active', 
                        ZabbixAlert.objectid.in_(triggers_in_batch),
                        ~ZabbixAlert.eventid.in_(current_event_ids),
                        ZabbixAlert.start_time >= limite_janela_busca 
                    ).update({
                        'status': 'resolved_auto',
                        'resolved_at': datetime.now(),
                        'last_seen': datetime.now(),
                        'hidden_on_dash': True,
                        'manual_group_id': None
                    }, synchronize_session=False)

                eids_to_ack = []
                alertas_para_salvar = [] 

                fechados_set = set()
                chunk_size = 1000
                for i in range(0, len(current_event_ids), chunk_size):
                    chunk = current_event_ids[i:i + chunk_size]
                    fechados_db = db.session.query(ZabbixAlert.eventid).filter(
                        ZabbixAlert.eventid.in_(chunk),
                        ZabbixAlert.status == 'resolved_manual',
                        ZabbixAlert.source_zabbix == fonte
                    ).all()
                    fechados_set.update(str(f[0]) for f in fechados_db)

                for p in problems:
                    eid = str(p['eventid'])
                    host_real = p.get('atlas_host', 'Desconhecido')
                    groups_real = p.get('atlas_groups', ['Geral'])
                    
                    if fonte == 'global' and len(times_shadow) > 0:
                        ignora_shadow = False
                        for g in groups_real:
                            if any(ts.upper() in g.upper() for ts in times_shadow):
                                ignora_shadow = True
                                break
                        if ignora_shadow:
                            continue 

                    opdata_real = p.get('atlas_opdata', '') 
                    trigger_name = p.get('name', 'Sem Título')
                    main_group = groups_real[0] if groups_real else 'Geral'
                    last_msg = p.get('atlas_last_msg', '')
                    severity_str = str(p['severity']) 
                    start_dt = datetime.fromtimestamp(int(p['clock']))
                    ack_status = int(p['acknowledged'])

                    silenciar_alerta = False
                    trigger_name_lower = trigger_name.lower()
                    host_real_lower = host_real.lower()
                    
                    try:
                        for regra in blacklist_compilada:
                            pertence_a_equipe = any(g in groups_real for g in regra['grupos_permitidos']) if regra['grupos_permitidos'] else True 

                            if pertence_a_equipe:
                                if regra['lista_restr'] and not any(g.lower() in regra['lista_restr'] for g in groups_real):
                                    continue

                                if regra['trigger_pat'] and regra['trigger_pat'] in trigger_name_lower:
                                    if not regra['host_pat'] or regra['host_pat'] in host_real_lower:
                                        silenciar_alerta = True
                                        if ack_status == 0:
                                            eids_to_ack.append(eid)
                                            ack_status = 1
                                            msg_silencio = "[ATLAS BOT] Reconhecido automaticamente."
                                            last_msg = msg_silencio if not last_msg else f"{msg_silencio} | {last_msg}"
                                            p['acknowledged'] = 1
                                        break
                    except Exception as e_triagem:
                        logger.error(f"Erro triagem blacklist: {e_triagem}")
                    
                    if not silenciar_alerta and ack_status == 0 and motor["auto_ack"]:
                        sev_ok = severity_str in motor["sevs"]
                        group_ok = len(motor["groups"]) == 0 or any(g in groups_real for g in motor["groups"])
                        
                        if sev_ok and group_ok:
                            eids_to_ack.append(eid)
                            last_msg = f"[ATLAS BOT] Reconhecido automaticamente. | {last_msg}" if last_msg else "[ATLAS BOT] Reconhecido automaticamente."
                            p['acknowledged'] = 1

                    status_real = 'active'
                    hora_resolucao = None
                    
                    if p.get('r_eventid') and str(p.get('r_eventid')) != "0":
                        status_real = 'resolved_auto'
                        hora_resolucao = datetime.now() 

                    hidden_dash = silenciar_alerta

                    if eid in fechados_set:
                        status_real = 'resolved_manual'
                        hora_resolucao = datetime.now()
                        hidden_dash = True

                    is_priority = False
                    try:
                        for rp in prio_compilada:
                            if rp['grupos_prio'] and not any(g.lower() in rp['grupos_prio'] for g in groups_real):
                                continue

                            if rp['trigger_pat'] and rp['trigger_pat'] in trigger_name_lower:
                                if not rp['host_pat'] or rp['host_pat'] in host_real_lower:
                                    is_priority = True
                                    break
                    except Exception as e_prio:
                        logger.error(f"Erro ao verificar prioridade: {e_prio}")

                    if is_priority:
                        expira_em = datetime.now() - timedelta(minutes=1)
                    else:
                        expira_em = datetime.now() + timedelta(minutes=motor["buffer_mins"])

                    alertas_para_salvar.append({
                        'eventid': eid,
                        'objectid': str(p['objectid']),
                        'host': host_real,
                        'host_group': main_group,
                        'name': trigger_name,
                        'severity': int(severity_str),
                        'description': opdata_real,
                        'start_time': start_dt,
                        'status': status_real,
                        'resolved_at': hora_resolucao, 
                        'last_seen': datetime.now(),
                        'atlas_created_at': datetime.now(),
                        'source_zabbix': fonte,
                        'ack_message': last_msg,
                        'hidden_on_dash': hidden_dash,
                        'buffer_expires_at': expira_em,
                        'buffer_notified': False,
                        'is_priority': is_priority
                    })

                if alertas_para_salvar:
                    alertas_para_salvar.sort(key=lambda x: int(x['eventid']))
                    stmt = pg_insert(ZabbixAlert).values(alertas_para_salvar)
                    stmt = stmt.on_conflict_do_update(
                        index_elements=['eventid', 'source_zabbix'],
                        set_={
                            'last_seen': datetime.now(),
                            'host': stmt.excluded.host,
                            'status': case(
                                (ZabbixAlert.status == 'resolved_manual', 'resolved_manual'),
                                else_=stmt.excluded.status
                            ),
                            'resolved_at': case(
                                (ZabbixAlert.status == 'resolved_manual', ZabbixAlert.resolved_at),
                                (stmt.excluded.status == 'resolved_auto', datetime.now()),
                                (stmt.excluded.status == 'resolved_manual', datetime.now()),
                                else_=ZabbixAlert.resolved_at
                            ),
                            'severity': stmt.excluded.severity,
                            'name': stmt.excluded.name,
                            'description': stmt.excluded.description,
                            'source_zabbix': stmt.excluded.source_zabbix,
                            'hidden_on_dash': case(
                                (ZabbixAlert.status == 'resolved_manual', True),
                                else_=stmt.excluded.hidden_on_dash
                            ),
                            'buffer_expires_at': case(
                                (stmt.excluded.is_priority == True, stmt.excluded.buffer_expires_at),
                                (ZabbixAlert.is_priority == True, stmt.excluded.buffer_expires_at),
                                else_=func.coalesce(ZabbixAlert.buffer_expires_at, stmt.excluded.buffer_expires_at)
                            ),
                            'buffer_notified': case(
                                (ZabbixAlert.status != 'active', False),
                                else_=ZabbixAlert.buffer_notified
                            ),
                            'is_priority': stmt.excluded.is_priority,
                            'ack_message': case(
                                (ZabbixAlert.ack_user_id.isnot(None), ZabbixAlert.ack_message),
                                (ZabbixAlert.ack_message.ilike('%[ATUADO]%'), ZabbixAlert.ack_message),
                                (stmt.excluded.ack_message != '', stmt.excluded.ack_message),
                                else_=ZabbixAlert.ack_message
                            )
                        }
                    )
                    db.session.execute(stmt) 
                    db.session.commit()

                if eids_to_ack:
                    from tasks import bg_zabbix_call_task
                    mapa_origem = {fonte: eids_to_ack}
                    try:
                        bg_zabbix_call_task.delay(mapa_origem, "[ATLAS BOT] Reconhecido automaticamente.", 6, None)
                    except Exception as celery_err:
                        logger.error(f"⚠️ Celery indisponível no Auto-Ack: {celery_err}")

                cutoff_time = datetime.now() - timedelta(days=days)
                limite_60_dias = datetime.now() - timedelta(days=60) 
                
                db_alerts_active = db.session.query(ZabbixAlert.eventid).filter(
                    ZabbixAlert.status == 'active',
                    ZabbixAlert.source_zabbix == fonte,
                    or_(
                        ZabbixAlert.start_time >= cutoff_time, 
                        and_(ZabbixAlert.severity.in_([4, 5]), ZabbixAlert.start_time >= limite_60_dias),
                        ZabbixAlert.name.ilike('%MON%'),       
                        ZabbixAlert.name.ilike('%HADES%')      
                    )
                ).all()
                
                db_ids = set(str(r[0]) for r in db_alerts_active)
                
                if db_ids: 
                    confirmed_alive_ids = set(current_event_ids)
                    truly_resolved_ids = list(db_ids - confirmed_alive_ids)
                    
                    if truly_resolved_ids:
                        try:
                            chunk_size = 100
                            mortos_confirmados = []
                            vivos_confirmados = []
                            
                            for i in range(0, len(truly_resolved_ids), chunk_size):
                                lote = truly_resolved_ids[i:i + chunk_size]
                                prova_vida = bridge._post("problem.get", {
                                    "eventids": lote,
                                    "output": ["eventid"]
                                })
                                
                                if prova_vida is not None and 'result' in prova_vida:
                                    vivos_no_lote = [str(p['eventid']) for p in prova_vida['result']]
                                    mortos_no_lote = list(set(lote) - set(vivos_no_lote))
                                    mortos_confirmados.extend(mortos_no_lote)
                                    vivos_confirmados.extend(vivos_no_lote)
                                else:
                                    logger.warning(f"🛡️ Zabbix engasgou na Prova de Vida. Preservando {len(lote)} alertas na tela.")
                            
                            if vivos_confirmados:
                                db.session.query(ZabbixAlert).filter(ZabbixAlert.eventid.in_(vivos_confirmados), ZabbixAlert.source_zabbix == fonte).update(
                                    {'last_seen': datetime.now()}, 
                                    synchronize_session=False
                                )

                            if mortos_confirmados:
                                db.session.query(ZabbixAlert).filter(ZabbixAlert.eventid.in_(mortos_confirmados), ZabbixAlert.source_zabbix == fonte).update(
                                    {'status': 'resolved_auto', 'resolved_at': datetime.now(), 'last_seen': datetime.now(), 'manual_group_id': None}, 
                                    synchronize_session=False
                                )
                                
                            db.session.commit()

                        except Exception as e_vida:
                            db.session.rollback()
                            logger.error(f"Erro na verificação de prova de vida: {e_vida}")

                ghost_key = f"zbx_ghost_check_{fonte}"
                if redis_db.set(ghost_key, "1", nx=True, ex=30): 
                    agora_ts = time.time()
                    eventos_resolvidos = bridge._post("event.get", {
                        "time_from": int(agora_ts) - 21600, 
                        "value": 0,          
                        "source": 0,         
                        "object": 0,         
                        "output": ["eventid"]
                    })

                    if eventos_resolvidos and 'result' in eventos_resolvidos:
                        ids_resolvidos = [str(e['eventid']) for e in eventos_resolvidos['result']]
                        if ids_resolvidos:
                            db.session.query(ZabbixAlert).filter(
                                ZabbixAlert.eventid.in_(ids_resolvidos),
                                ZabbixAlert.status == 'active',
                                ZabbixAlert.source_zabbix == fonte
                            ).update(
                                {
                                    'status': 'resolved_auto', 
                                    'last_seen': datetime.now(),
                                    'resolved_at': datetime.now(),
                                    'hidden_on_dash': True,
                                    'manual_group_id': None
                                }, 
                                synchronize_session=False
                            )
                            db.session.commit() 

            db.session.execute(text("""
                UPDATE zabbix_alert
                SET procedimento_id_manual = sub.doc_id
                FROM (
                    SELECT name, MAX(procedimento_id_manual) as doc_id
                    FROM zabbix_alert
                    WHERE procedimento_id_manual IS NOT NULL
                    GROUP BY name
                ) sub
                WHERE zabbix_alert.name = sub.name 
                  AND zabbix_alert.procedimento_id_manual IS NULL 
                  AND zabbix_alert.status = 'active';
            """))
            db.session.commit()
            return True
            
        except Exception as e:
            db.session.rollback()
            print(f"🔥 ERRO CRÍTICO NO SYNC DO ZABBIX: {e}", flush=True) 
            return False

def get_alerts_json(user_id=None, since_ts=0):
    try:
        db.session.commit()
        db.session.expire_all()

        desde_data = datetime.fromtimestamp(since_ts) if since_ts > 0 else (datetime.now() - timedelta(hours=24))
        
        data_corte_resolvidos = (
            (datetime.fromtimestamp(since_ts) - timedelta(minutes=60)) if since_ts > 0
            else (datetime.now() - timedelta(hours=24))
        )

        users_map_json = redis_db.get("atlas_users_map")
        if users_map_json:
            users_map = json.loads(users_map_json)
        else:
            users_map = {str(u.id): u.display_name for u in User.query.all()}
            redis_db.setex("atlas_users_map", 300, json.dumps(users_map))
        
        config = AtlasConfig.query.first()
        buffer_minutes_defined = config.buffer_minutes if config else 5

        team_configs_json = redis_db.get("atlas_team_configs_full")
        if team_configs_json:
            team_configs_cached = json.loads(team_configs_json)
        else:
            team_configs_db = TeamZabbixConfig.query.all()
            team_configs_cached = [{
                'team_name': tc.team_name,
                'zabbix_url': tc.zabbix_url,
                'auto_ack_enabled': tc.auto_ack_enabled,
                'whitelist_groups': tc.whitelist_groups,
                'buffer_minutes': tc.buffer_minutes
            } for tc in team_configs_db]
            redis_db.setex("atlas_team_configs_full", 300, json.dumps(team_configs_cached))

        urls_motores = {tc['team_name']: tc['zabbix_url'].rstrip('/') for tc in team_configs_cached if tc.get('zabbix_url')}

        team_configs_map = {}
        for tc in team_configs_cached:
            team_configs_map[tc['team_name']] = {
                'auto_ack': tc['auto_ack_enabled'],
                'groups': [g.strip() for g in tc['whitelist_groups'].split(',')] if tc.get('whitelist_groups') else [],
                'buffer_minutes': tc['buffer_minutes']
            }
        
        global_auto_ack = config.auto_ack_enabled if config else False
        global_groups = [g.strip() for g in config.auto_ack_groups.split(',')] if config and config.auto_ack_groups else []

        query_tickets = Noticia.query.filter(
            Noticia.status_problema != 'Resolvido'
        ).options(
            load_only(
                Noticia.id, Noticia.zabbix_url, Noticia.status_problema, 
                Noticia.equipe, Noticia.tag, Noticia.resumo, Noticia.titulo, 
                Noticia.autor_id, Noticia.responsavel_id, Noticia.analista_externo, 
                Noticia.data_criacao, Noticia.conteudo
            ),
            joinedload(Noticia.responsavel),
            joinedload(Noticia.autor)
        )
        
        try:
            from flask import has_request_context
            if has_request_context() and current_user and current_user.is_authenticated:
                is_master = getattr(current_user.role, 'name', '') == 'master_admin'
                if not is_master:
                    user_teams = current_user.teams.split(',') if current_user.teams else []
                    equipe_usuario = user_teams[0].strip() if user_teams else 'Geral'
                    
                    usuarios_time = User.query.filter(User.teams.ilike(f"%{equipe_usuario}%")).all()
                    ids_meu_time = [u.id for u in usuarios_time]
                    
                    query_tickets = query_tickets.filter(
                        or_(Noticia.equipe == equipe_usuario, Noticia.autor_id.in_(ids_meu_time))
                    )
        except Exception as e:
            pass
            
        active_tickets = query_tickets.all()
        
        ticket_map = {}
        tickets_processados = set() 
        
        for t in active_tickets:
            if t.zabbix_url:
                match = re.search(r'eventid=(\d+)', str(t.zabbix_url))
                if match:
                    ev_id = match.group(1)
                    ticket_map[ev_id] = t

        agora = datetime.now()
        condicoes_busca = []

        if since_ts == 0:
            condicoes_busca.append(
                and_(
                    ZabbixAlert.status == 'active',
                    or_(
                        ZabbixAlert.severity.in_([4, 5]),
                        ZabbixAlert.eventid.in_(list(ticket_map.keys()))
                    )
                )
            )
            condicoes_busca.append(
                and_(
                    ZabbixAlert.status.in_(['resolved_auto', 'resolved_manual']),
                    ZabbixAlert.severity.in_([4, 5]),
                    ZabbixAlert.resolved_at >= data_corte_resolvidos
                )
            )
        else:
            condicoes_busca.append(
                and_(
                    or_(
                        ZabbixAlert.severity.in_([4, 5]),
                        ZabbixAlert.eventid.in_(list(ticket_map.keys()))
                    ),
                    ZabbixAlert.last_seen >= desde_data
                )
            )
            condicoes_busca.append(
                and_(
                    ZabbixAlert.status == 'active',
                    ZabbixAlert.severity.in_([4, 5]),
                    ZabbixAlert.buffer_expires_at <= agora,
                    ZabbixAlert.buffer_expires_at >= desde_data
                )
            )

        db_alerts = ZabbixAlert.query\
            .options(
                joinedload(ZabbixAlert.cliente_vinculado),
                joinedload(ZabbixAlert.procedimento_vinculado),
                joinedload(ZabbixAlert.cenario_vinculado),
                joinedload(ZabbixAlert.equipe_vinculada)
            )\
            .filter(or_(*condicoes_busca))\
            .order_by(desc(ZabbixAlert.start_time))\
            .all()

        if since_ts > 0:
            hosts_com_crise = set(
                (a.host, a.source_zabbix) for a in db_alerts if a.severity == 5 and a.status == 'active'
            )
            
            if hosts_com_crise:
                pares_ja_buscados = set((a.eventid, a.source_zabbix) for a in db_alerts)
                
                condicoes_irmaos = [
                    and_(ZabbixAlert.host == host, ZabbixAlert.source_zabbix == source)
                    for host, source in hosts_com_crise
                ]
                
                irmaos_perdidos = ZabbixAlert.query.options(
                    joinedload(ZabbixAlert.cliente_vinculado),
                    joinedload(ZabbixAlert.procedimento_vinculado),
                    joinedload(ZabbixAlert.cenario_vinculado)
                ).filter(
                    or_(*condicoes_irmaos),
                    ZabbixAlert.severity == 5,
                    ZabbixAlert.status == 'active'
                ).all()
                
                # eventid se repete entre Zabbix diferentes: o filtro é por (eventid, origem), em Python
                db_alerts.extend(
                    i for i in irmaos_perdidos
                    if (i.eventid, i.source_zabbix) not in pares_ja_buscados
                )

            # 🧩 GRUPOS MANUAIS: no delta o pai manual só pode ser montado com TODOS os membros;
            # senão o front substitui o pai completo por um pai parcial (id estável mass_m_<grp>)
            grupos_manuais = set(
                a.manual_group_id for a in db_alerts
                if getattr(a, 'manual_group_id', None) and a.status == 'active'
            )
            if grupos_manuais:
                ja_buscados = set((a.eventid, a.source_zabbix) for a in db_alerts)
                membros_manuais = ZabbixAlert.query.options(
                    joinedload(ZabbixAlert.cliente_vinculado),
                    joinedload(ZabbixAlert.procedimento_vinculado),
                    joinedload(ZabbixAlert.cenario_vinculado),
                    joinedload(ZabbixAlert.equipe_vinculada)
                ).filter(
                    ZabbixAlert.manual_group_id.in_(list(grupos_manuais)),
                    ZabbixAlert.status == 'active'
                ).all()
                for m in membros_manuais:
                    if (m.eventid, m.source_zabbix) not in ja_buscados:
                        db_alerts.append(m)

        try:
            from models import AlertBlacklist
            agora = datetime.now()
            
            regras_blacklist = AlertBlacklist.query.filter(
                AlertBlacklist.is_active == True,
                or_(
                    AlertBlacklist.expiration_date == None, 
                    AlertBlacklist.expiration_date > agora
                )
            ).all()

            regras_otimizadas = []
            for regra in regras_blacklist:
                grupos = [g.strip().lower() for g in regra.host_groups.split(',') if g.strip()] if getattr(regra, 'host_groups', None) else []
                regras_otimizadas.append({
                    'grupos': grupos,
                    'trigger_pat': (regra.trigger_pattern or '').lower(),
                    'host_pat': (regra.host_pattern or '').lower()
                })

            alertas_filtrados = []
            hidden_alerts_map = {} 

            for alert in db_alerts:
                if alert.hidden_on_dash:
                    hidden_alerts_map[str(alert.eventid)] = True
                    alertas_filtrados.append(alert)
                    continue

                nome_alerta = (alert.name or '').lower()
                host_alerta = (alert.host or '').lower()
                grupo_alerta_lower = (alert.host_group or 'geral').lower()

                ocultar = False
                for r in regras_otimizadas:
                    if r['grupos'] and grupo_alerta_lower not in r['grupos']:
                        continue

                    if r['trigger_pat'] and r['trigger_pat'] in nome_alerta:
                        if not r['host_pat'] or r['host_pat'] in host_alerta:
                            ocultar = True 
                            break

                if ocultar:
                    hidden_alerts_map[str(alert.eventid)] = True 
                    
                alertas_filtrados.append(alert) 

            db_alerts = alertas_filtrados
        except Exception as e_bl:
            pass

        limite_48h = datetime.now() - timedelta(hours=48)
        
        object_ids_ativos = list(set([str(a.objectid) for a in db_alerts if a.objectid]))
        
        recorrencia_map = {}
        if object_ids_ativos:
            contagem = db.session.query(
                ZabbixAlert.objectid,
                func.count(ZabbixAlert.id)
            ).filter(
                ZabbixAlert.objectid.in_(object_ids_ativos),
                ZabbixAlert.start_time >= limite_48h
            ).group_by(ZabbixAlert.objectid).all()
            
            for obj_id, count in contagem:
                recorrencia_map[str(obj_id)] = count

        formatted_response = []
        
        for alert_db in db_alerts:
            base_time = alert_db.start_time
            delta = datetime.now() - base_time
            seconds_active = delta.total_seconds()
            minutes_active = int(seconds_active / 60)
            
            ack_user_id = str(alert_db.ack_user_id) if alert_db.ack_user_id else None
            last_msg = alert_db.ack_message or ""
            
            str_event_id = str(alert_db.eventid)

            total_buffer_seconds = buffer_minutes_defined * 60 
            buffer_seconds_left = 0
            
            ticket_info = None 
            stage = "buffer" 
            owner_name = None

            is_hidden_by_blacklist = alert_db.hidden_on_dash or hidden_alerts_map.get(str_event_id, False)
       
            minutos_de_vida = seconds_active / 60.0
            buffer_seconds_left = 0 
            
            if alert_db.source_zabbix and alert_db.source_zabbix != 'global' and alert_db.source_zabbix in team_configs_map:
                tc_data = team_configs_map[alert_db.source_zabbix]
                grupo_tem_automacao = tc_data['auto_ack'] and (len(tc_data['groups']) == 0 or alert_db.host_group in tc_data['groups'])
                current_buffer_mins = tc_data.get('buffer_minutes') if tc_data.get('buffer_minutes') is not None else buffer_minutes_defined
            else:
                grupo_tem_automacao = global_auto_ack and (len(global_groups) == 0 or alert_db.host_group in global_groups)
                current_buffer_mins = buffer_minutes_defined
                
            has_automation = grupo_tem_automacao
            total_buffer_seconds = current_buffer_mins * 60
            
            if user_id and ack_user_id == str(user_id):
                if "[ATUADO]" in last_msg.upper(): 
                    stage = "acted"
                else:
                    stage = "validation"
                owner_name = "Você"

                if str_event_id in ticket_map:
                    t_desk = ticket_map[str_event_id]
                    tickets_processados.add(t_desk.id)
                    ticket_info = {
                        "id": t_desk.id, 
                        "status": t_desk.status_problema, 
                        "dono": t_desk.analista_externo if t_desk.analista_externo else (t_desk.responsavel.display_name.split()[0] if t_desk.responsavel else 'Sistema'),
                        "equipe": t_desk.equipe, 
                        "cliente": t_desk.resumo,
                        "autor_teams": t_desk.autor.teams if t_desk.autor else 'Geral',
                        "zabbix_url": t_desk.zabbix_url
                    }

            elif str_event_id in ticket_map:
                stage = "tracking"
                t_desk = ticket_map[str_event_id]
                tickets_processados.add(t_desk.id)
                
                nome_dono = t_desk.analista_externo if t_desk.analista_externo else (t_desk.responsavel.display_name.split()[0] if t_desk.responsavel else 'Sistema')
                owner_name = nome_dono

                ack_user_id = str(t_desk.responsavel_id) if t_desk.responsavel_id else ack_user_id
                
                ticket_info = {
                    "id": t_desk.id, 
                    "status": t_desk.status_problema, 
                    "dono": nome_dono,
                    "equipe": t_desk.equipe, 
                    "cliente": t_desk.resumo,
                    "autor_teams": t_desk.autor.teams if t_desk.autor else 'Geral',
                    "zabbix_url": t_desk.zabbix_url
                }
            elif is_hidden_by_blacklist and ack_user_id != str(user_id):
                stage = "blacklist"
                owner_name = "Atlas Bot"
                
            elif "[Interno] Monitorando" in last_msg:
                stage = "validation"
                owner_name = users_map.get(ack_user_id, "Analista")
                
            elif ack_user_id and "[ATLAS BOT]" not in last_msg:
                stage = "general"
                owner_name = users_map.get(ack_user_id, "Analista")
                
            else: 
                if minutos_de_vida < current_buffer_mins:
                    buffer_seconds_left = total_buffer_seconds - seconds_active
                    stage = "buffer" 
                else:
                    buffer_seconds_left = 0
                    stage = "action" 

                if "[ATLAS BOT]" in last_msg: 
                    owner_name = "Atlas Bot"
            
            dur_str = "" 

            vinculo_dict = None
            if alert_db.cliente_vinculado or alert_db.equipe_vinculada:
                vinculo_dict = {
                    "cliente": alert_db.cliente_vinculado.nome if alert_db.cliente_vinculado else "N/A",
                    "equipe": alert_db.equipe_vinculada.nome if alert_db.equipe_vinculada else "Geral"
                }

            base_url_zabbix = urls_motores.get(alert_db.source_zabbix, ZABBIX_FRONT_URL)
            link_completo_alerta = f"{base_url_zabbix}/tr_events.php?triggerid={alert_db.objectid}&eventid={alert_db.eventid}"

            formatted_response.append({
                "id": alert_db.eventid, 
                "objectid": alert_db.objectid, 
                "host": alert_db.host,
                "manual_group_id": getattr(alert_db, 'manual_group_id', None), # 🌟 INJETADO AQUI
                "group": alert_db.host_group,
                "groups": [alert_db.host_group] if alert_db.host_group else ["Geral"],
                "trigger": alert_db.name,
                "severity": alert_db.severity,
                "opdata": alert_db.description,
                "duration": dur_str,
                "start_date": alert_db.start_time.strftime('%d/%m %H:%M'),
                "timestamp": base_time.timestamp(),
                "owner_id": ack_user_id,
                "owner_name": owner_name,
                "stage": stage,
                "buffer_seconds_left": buffer_seconds_left,
                "has_automation": has_automation,                
                "buffer_max_seconds": total_buffer_seconds,      
                "doc_id": alert_db.procedimento_id_manual if alert_db.procedimento_id_manual else 0,
                "vinculo": vinculo_dict,
                "ticket": ticket_info,
                "zabbix_is_resolved": alert_db.status != 'active',
                "history_count": recorrencia_map.get(str(alert_db.objectid), 1),
                "history_last_user": "",
                "last_msg": last_msg, 
                "source_zabbix": alert_db.source_zabbix,
                "zabbix_links": [link_completo_alerta],
                "is_priority": getattr(alert_db, 'is_priority', False)
            })

        for t in active_tickets:
            if t.id not in tickets_processados:
                dur_str_t = "" 

                nome_dono_t = t.analista_externo if t.analista_externo else (t.responsavel.display_name.split()[0] if t.responsavel else 'Sistema')
                opdata_clean = re.sub(r'<[^>]+>', '', t.conteudo) if t.conteudo else ''
                
                formatted_response.append({
                    "id": f"desk_{t.id}",
                    "objectid": "0", 
                    "host": t.resumo or "Cliente Indefinido", 
                    "group": t.equipe or t.tag or "Geral",
                    "groups": [t.equipe or t.tag] if (t.equipe or t.tag) else ["Geral"],
                    "trigger": t.titulo or "Chamado Manual",
                    "severity": 1, 
                    "opdata": opdata_clean[:120] + "..." if len(opdata_clean) > 120 else opdata_clean,
                    "duration": dur_str_t,
                    "start_date": t.data_criacao.strftime('%d/%m %H:%M'),
                    "timestamp": t.data_criacao.timestamp(), 
                    "owner_id": t.responsavel_id,
                    "owner_name": f"Ticket #{t.id}",
                    "stage": "tracking",
                    "buffer_seconds_left": 0,
                    "has_automation": False,                
                    "buffer_max_seconds": 0,      
                    "doc_id": 0,
                    "vinculo": None,
                    "ticket": {
                        "id": t.id, "status": t.status_problema, "dono": nome_dono_t,
                        "equipe": t.equipe, "cliente": t.resumo,
                        "autor_teams": t.autor.teams if t.autor else 'Geral', 
                        "zabbix_url": t.zabbix_url 
                    },
                    "zabbix_is_resolved": False,
                    "history_count": 0,
                    "history_last_user": "",
                    "last_msg": "Acompanhamento de chamado ativo no Atlas Desk",
                    "source_zabbix": "desk"
                })

        import hashlib
        import time
        final_response = []
        
        agora_ts = time.time()
        limite_24h_ts = agora_ts - 86400 
        
        host_buckets = defaultdict(list)
        
        # 🌟 NOVO: Dicionário para capturar agrupamentos manuais feitos via botão
        manual_buckets = defaultdict(list)

        for a in formatted_response:
            # 1. Pega os agrupamentos MANUAIS feitos pelo botão (Apenas em Meus Alertas e Atuados)
            manual_id = a.get('manual_group_id') # <--- CORREÇÃO AQUI (Trocado getattr pelo .get() do dicionário)
            if manual_id and a.get('stage') in ['validation', 'acted']:
                if a.get('zabbix_is_resolved', False):
                    final_response.append(a)  # 🌟 Já resolveu: sai do grupo, vira card solo
                else:
                    manual_buckets[manual_id].append(a)
                continue

            # 2. Agrupamento AUTOMÁTICO (Mantido para Disaster/Sev 5 nas abas Meus Alertas e Atuados)
            if int(a['severity']) != 5 or a.get('zabbix_is_resolved', False) or a.get('stage') not in ['validation', 'acted']:
                final_response.append(a)
                continue
                
            chave_agrupamento = (a['host'], a['severity'], a['group'], a.get('owner_id'), a.get('stage'), a.get('source_zabbix') or 'global')
            host_buckets[chave_agrupamento].append(a)

        # 🌟 3. PROCESSA OS BUCKETS MANUAIS (Sem limite de tempo!)
        for m_id, cluster in manual_buckets.items():
            if len(cluster) >= 2:
                cluster.sort(key=lambda x: x['timestamp'], reverse=True)
                parent = cluster[0].copy()
                
                # Coleta todos os IDs filhos
                todos_filhos_ids = []
                for item in cluster:
                    todos_filhos_ids.extend(item.get('all_event_ids', [item['id']]))

                parent['id'] = f"mass_m_{m_id}"
                parent['is_parent'] = True
                parent['child_count'] = len(todos_filhos_ids) - 1
                parent['child_ids'] = todos_filhos_ids
                parent['child_data'] = cluster
                parent['trigger'] = f"📦 AGRUPAMENTO MANUAL ({len(todos_filhos_ids)} incidentes)"
                parent['opdata'] = f"Grupo unificado manualmente no Atlas com {len(todos_filhos_ids)} alertas selecionados."
                
                final_response.append(parent)
            else:
                final_response.extend(cluster)

        for chave, cluster in host_buckets.items():
            cluster.sort(key=lambda x: x['timestamp'], reverse=True) 
            dedup_map = {}
            for a in cluster:
                chave_dedup = (a['objectid'], a.get('source_zabbix') or 'global')  # objectid não é único entre Zabbix
                if chave_dedup not in dedup_map:
                    a['all_event_ids'] = [a['id']] # 🌟 Cria a sacola de irmãos
                    a['_first_ts'] = a['timestamp']  # 🧬 evento mais antigo do trigger (inclui os escondidos)
                    dedup_map[chave_dedup] = a
                else:
                    dedup_map[chave_dedup]['all_event_ids'].append(a['id']) # 🌟 Coloca o irmão escondido na sacola
                    dedup_map[chave_dedup]['_first_ts'] = min(dedup_map[chave_dedup]['_first_ts'], a['timestamp'])
            cluster = list(dedup_map.values())

            cluster.sort(key=lambda x: x['timestamp'])
            
            sub_clusters = []
            grupo_atual = []
            
            for a in cluster:
                if not grupo_atual:
                    grupo_atual.append(a)
                else:
                    if (a['timestamp'] - grupo_atual[0]['timestamp']) <= 600:
                        grupo_atual.append(a)
                    else:
                        sub_clusters.append(grupo_atual)
                        grupo_atual = [a]
            
            if grupo_atual:
                sub_clusters.append(grupo_atual)
                
            for sub_cluster in sub_clusters:
                if len(sub_cluster) >= 2: 
                    parent = sub_cluster[0].copy()
                    
                    for c in sub_cluster:
                        if c.get('ticket'):
                            parent['ticket'] = c['ticket']
                            parent['stage'] = 'tracking' 
                            break
                    
                    # 🧬 ID estável: usa o evento MAIS ANTIGO de todo o grupo (inclusive os escondidos pelo dedup).
                    # Antes usava o timestamp do representante (o mais novo do trigger), então quando um
                    # evento repetido chegava o id do grupo mudava e o front duplicava o card.
                    primeiro_ts = min(c.get('_first_ts', c['timestamp']) for c in sub_cluster)
                    hash_base = f"{chave[0]}_{chave[1]}_{chave[2]}_{chave[3]}_{chave[5]}_{primeiro_ts}"
                    import hashlib
                    stable_id = "mass_" + hashlib.md5(hash_base.encode('utf-8')).hexdigest()[:12]
                    
                    # 🌟 Extrai TODOS os IDs espremidos no dedup para o fechamento
                    todos_filhos_ids = []
                    for a in sub_cluster:
                        todos_filhos_ids.extend(a.get('all_event_ids', [a['id']]))
                    
                    parent['id'] = stable_id
                    parent['is_parent'] = True
                    parent['child_count'] = len(todos_filhos_ids) - 1 # 👈 Agora exibe no card a contagem exata que será fechada
                    parent['child_ids'] = todos_filhos_ids
                    parent['child_data'] = sub_cluster
                    parent['stage'] = sub_cluster[0].get('stage', 'buffer') 
                    parent['last_msg'] = sub_cluster[0].get('last_msg', '') 
                    
                    parent['zabbix_is_resolved'] = all(c.get('zabbix_is_resolved', False) for c in sub_cluster)
                    parent['is_priority'] = any(c.get('is_priority', False) for c in sub_cluster)
                    
                    parent['trigger'] = f"🔥 MÚLTIPLOS ALERTAS CRÍTICOS ({len(sub_cluster)} incidentes)"
                    
                    causa_raiz = parent.get('opdata', '')
                    parent['opdata'] = f"O Atlas agrupou {len(sub_cluster)} alertas Disaster neste servidor. Causa raiz: {causa_raiz}" 
                    
                    final_response.append(parent)
                else:
                    final_response.extend(sub_cluster)
        
        final_response.sort(key=lambda x: x['timestamp'], reverse=True)

        stage_counts = {"buffer": 0, "action": 0, "validation": 0, "tracking": 0, "general": 0, "blacklist": 0, "acted": 0}
        
        for a in final_response:
            stg = a.get('stage', 'buffer')
            if stg in stage_counts:
                stage_counts[stg] += 1
            if stg != "blacklist":
                stage_counts["general"] += 1

        import time 
        
        return {
            "alerts": final_response,
            "total_active": len(final_response),
            "stage_counts": stage_counts,
            "server_timestamp": time.time()
        }

    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro Get JSON: {e}")
        return {"alerts": [], "total_active": 0, "stage_counts": {}}

class ZabbixBridge:
    def __init__(self, front_url=ZABBIX_FRONT_URL, user=ZABBIX_MASTER_USER, password=ZABBIX_MASTER_PASS):
        clean_url = front_url.split('/zabbix.php')[0].split('/api_jsonrpc.php')[0].rstrip('/')
        self.front_url = clean_url
        self.api_url = f"{self.front_url}/api_jsonrpc.php"
        self.user = user
        self.password = password
        self.master_token = None
        self.last_login = 0
        self.group_id_cache = {} 
        self._session = None

    def get_session(self):
        """Cria a sessão isolada com Pooling ativado (Mantém os túneis TCP abertos e rápidos)"""
        if self._session is None:
            self._session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=1)
            self._session.mount('http://', adapter)
            self._session.mount('https://', adapter)
        return self._session

    def _post(self, method, params, token=None):
        # Chaves exclusivas para este servidor Zabbix no Redis
        lock_key = f"zbx_cb_lock_{self.front_url}"
        fails_key = f"zbx_cb_fails_{self.front_url}"

        # 1. Se a trava existir no Redis, aborta na hora (Protege os outros workers)
        if redis_db.exists(lock_key):
            return None 

        if not token:
            if not self.master_token or (time.time() - self.last_login > 14400):
                self.login_master()
            token = self.master_token

        payload = {
            "jsonrpc": "2.0", "method": method, "params": params, "auth": token, "id": 1
        }
        
        session = self.get_session()
        
        try:
            try:
                # 🌟 TEMPO AUMENTADO: 10s para tentar conectar, 30s para receber os dados
                r = session.post(self.api_url, json=payload, timeout=(10.0, 30.0), verify=False) 
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                if self.front_url == ZABBIX_FRONT_URL and 'ZABBIX_FRONT_URL_FALLBACK' in globals() and ZABBIX_FRONT_URL_FALLBACK:
                    self.front_url = ZABBIX_FRONT_URL_FALLBACK
                    self.api_url = f"{self.front_url}/api_jsonrpc.php"
                    r = session.post(self.api_url, json=payload, timeout=(10.0, 30.0), verify=False)
                else:
                    raise e
                    
            res = r.json()
            
            # 2. SUCESSO: Zera as falhas no Redis
            redis_db.delete(fails_key)
            
            if 'error' in res and 'Not authorized' in str(res['error']):
                if token == self.master_token:
                    if self.login_master():
                        payload['auth'] = self.master_token
                        return session.post(self.api_url, json=payload, timeout=(10.0, 30.0), verify=False).json()
            return res

        except requests.exceptions.Timeout:
            # 3. TIMEOUT: Soma 1 falha no Redis de forma atômica
            fails = redis_db.incr(fails_key)
            logger.error(f"Timeout Zabbix ({self.front_url}). Falha {fails}/10.")
            
            # Amaciou a trava: Agora tolera 10 falhas e tranca por apenas 30 segundos
            if fails >= 10:
                redis_db.setex(lock_key, 30, "locked")
                redis_db.delete(fails_key)
            return None 
            
        except Exception as e:
            logger.error(f"Erro conexao Zabbix ({self.front_url}): {e}")
            return None

    def login_master(self):
        if len(self.password) >= 32 and (self.user.lower() in ['token', 'api', 'atlas'] or len(self.password) == 64):
            self.master_token = self.password
            self.last_login = time.time() + 31536000 
            return True
            
        session = self.get_session()
        try:
            payload = {"jsonrpc": "2.0", "method": "user.login", "params": {"username": self.user, "password": self.password}, "id": 1}
            try:
                r = session.post(self.api_url, json=payload, timeout=5, verify=False)
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                if self.front_url == ZABBIX_FRONT_URL and 'ZABBIX_FRONT_URL_FALLBACK' in globals() and ZABBIX_FRONT_URL_FALLBACK:
                    self.front_url = ZABBIX_FRONT_URL_FALLBACK
                    self.api_url = f"{self.front_url}/api_jsonrpc.php"
                    r = session.post(self.api_url, json=payload, timeout=5, verify=False)
                else:
                    raise e
                    
            res = r.json()
            if 'result' not in res:
                payload["params"] = {"user": self.user, "password": self.password}
                r = session.post(self.api_url, json=payload, timeout=5, verify=False)
                res = r.json()
                
            if 'result' in res:
                self.master_token = res['result']
                self.last_login = time.time()
                return True
            return False
        except Exception as e:
            logger.error(f"Erro no login master Zabbix: {e}")
            return False

    def user_auth(self, username, password):
        session = self.get_session()
        try:
            # Tenta o padrão novo Zabbix V7/V6.4 ("username")
            payload = {"jsonrpc": "2.0", "method": "user.login", "params": {"username": username, "password": password}, "id": 1}
            r = session.post(self.api_url, json=payload, timeout=5, verify=False)
            res = r.json()
            
            # Se falhar, tenta o fallback para o padrão legado Zabbix V4 ("user")
            if 'result' not in res:
                payload["params"] = {"user": username, "password": password}
                r = session.post(self.api_url, json=payload, timeout=5, verify=False)
                res = r.json()
                
            return res.get('result')
        except: return None
        
    # As funções get_all_hostgroups, get_group_ids, get_enriched_problems e interact continuam idênticas...

    def get_all_hostgroups(self):
        res = self._post("hostgroup.get", {"output": ["groupid", "name"], "real_hosts": True, "sortfield": "name"})
        # 🛡️ PROTEÇÃO: Garante que res não é None antes de dar .get()
        return res.get('result', []) if res else []

    def get_group_ids(self, group_names):
        if not group_names: return None
        missing = [g for g in group_names if g not in self.group_id_cache]
        if missing:
            res = self._post("hostgroup.get", {"output": ["groupid", "name"], "filter": {"name": missing}})
            # 🛡️ PROTEÇÃO AQUI
            if res:
                for g in res.get('result', []):
                    self.group_id_cache[g['name']] = g['groupid']
        ids = [self.group_id_cache[g] for g in group_names if g in self.group_id_cache]
        return ids if ids else None

    def get_enriched_problems(self, groups=None, specific_ids=None, days=7, fetch_mon_unlimited=False, fetch_all_high_crit=False):
        # Aumentamos a "memória" de 5 mil para 30 mil Triggers

        if specific_ids:
            time_from = 0 
        else:
            time_from = int(time.time() - (days * 86400))

        params = {
            "output": ["eventid", "objectid", "name", "clock", "severity", "opdata", "acknowledged", "r_eventid"],
            "select_acknowledges": "extend", 
            "selectTags": "extend",
            "sortfield": ["eventid"], "sortorder": "DESC", "time_from": time_from 
        }
        
        if specific_ids:
            params["eventids"] = specific_ids
        
        p_res = self._post("problem.get", params)
        
        # 🛡️ BLINDAGEM ANTI-FALSE EMPTY: Se a rede falhou e retornou Nulo, aborta a extração.
        if p_res is None:
            return None
        
        if 'error' in p_res and 'select_acknowledges' in str(p_res.get('error', '')):
            del params['select_acknowledges']
            params['selectAcknowledges'] = "extend"
            p_res = self._post("problem.get", params)
            
            # Revalida caso o fallback também sofra falha de rede
            if p_res is None:
                return None
        
        if 'result' not in p_res: return None
        
        problems = p_res.get('result', [])

        seen_events = set([p['eventid'] for p in problems])

        # ==============================================================
        # MÁGICA DOS MONs E HADES: Busca ILIMITADA no tempo (Puxa TUDO)
        # ==============================================================
        if fetch_mon_unlimited and not specific_ids:
            params_mon = params.copy()
            params_mon["time_from"] = 0  # 🌟 ZERO TRAVAS PARA O MON
            params_mon["search"] = {"name": "MON"}
            p_mon_res = self._post("problem.get", params_mon)
            
            # 🛡️ Trava de segurança para a sub-consulta
            if p_mon_res is not None:
                for mp in p_mon_res.get('result', []):
                    if mp['eventid'] not in seen_events:
                        problems.append(mp)
                        seen_events.add(mp['eventid'])
            
            params_hades = params.copy()
            params_hades["time_from"] = 0  # 🌟 ZERO TRAVAS PARA O HADES
            params_hades["search"] = {"name": "HADES"}
            p_hades_res = self._post("problem.get", params_hades)
            
            # 🛡️ Trava de segurança para a sub-consulta
            if p_hades_res is not None:
                for hp in p_hades_res.get('result', []):
                    if hp['eventid'] not in seen_events:
                        problems.append(hp)
                        seen_events.add(hp['eventid'])

        # ==============================================================
        # MÁGICA DOS CRÔNICOS: Severidade 4 e 5 (Limite de 60 dias)
        # ==============================================================
        if fetch_all_high_crit and not specific_ids:
            params_crit = params.copy()
            params_crit["time_from"] = int(time.time() - (60 * 86400)) # 🛡️ Trava de 60 dias aqui!
            params_crit["severities"] = [4, 5]
            p_crit_res = self._post("problem.get", params_crit)
            
            # 🛡️ Trava de segurança para a sub-consulta
            if p_crit_res is not None:
                for cp in p_crit_res.get('result', []):
                    if cp['eventid'] not in seen_events:
                        problems.append(cp)
                        seen_events.add(cp['eventid'])
        # ==============================================================

        if not problems: return []

        missing_trigger_ids = []
        trigger_age_map = {} 
        agora_ts = int(time.time())

        for p in problems:
            tid = str(p['objectid'])
            # Salva o horário do evento para calcularmos a idade
            trigger_age_map[tid] = int(p['clock'])

            # Pergunta pro Redis se ele tem a trigger (ISOLADO POR ZABBIX)
            cache_key = f"zbx_trig_{self.front_url}_{tid}"
            if not redis_db.exists(cache_key): 
                missing_trigger_ids.append(tid)
        
        if missing_trigger_ids:
            missing_unique = list(set(missing_trigger_ids))
            t_res = self._post("trigger.get", {
                "triggerids": missing_unique,
                "output": ["triggerid", "description", "status", "state"], 
                "selectHosts": ["name", "host", "status"],        
                "selectGroups": ["name"],
                "selectItems": ["name", "lastvalue", "units", "status", "state"] 
            })
            
            # 🛡️ Trava de segurança para a sub-consulta de triggers
            if t_res is not None:
                for t in t_res.get('result', []): 
                    tid = str(t['triggerid'])
                    idade_segundos = agora_ts - trigger_age_map.get(tid, agora_ts)
                    
                    # 👇 O PONTO DE EQUILÍBRIO: 5 minutos (300s) para alertas novos, 1 hora para velhos.
                    # Reduz 80% das requisições sem atrasar o retorno de manutenções!
                    ttl_dinamico = 300 if idade_segundos < 86400 else 3600
                    
                    # Salva no Redis (ISOLADO POR ZABBIX)
                    cache_key = f"zbx_trig_{self.front_url}_{tid}"
                    redis_db.setex(cache_key, ttl_dinamico, json.dumps(t))

        final_data = []
        seen = set()
        
        for p in problems:
            eid = p['eventid']
            if eid in seen: continue
            seen.add(eid)
            
            tid = str(p['objectid'])
            cache_key = f"zbx_trig_{self.front_url}_{tid}"
            cached_t = redis_db.get(cache_key)
            # Lê do Redis e converte de volta pra dicionário
            t_data = json.loads(cached_t) if cached_t else {}

            # =================================================================
            # 🛡️ PROTEÇÃO ANTI-ZUMBI (ÓRFÃOS SEM HOST/TRIGGER NO ZABBIX)
            # Se o Zabbix deletou o objeto mas deixou o evento ativo, ignoramos.
            # =================================================================
            if not t_data or not t_data.get('hosts'):
                continue
            # =================================================================

            trigger_status = int(t_data.get('status', 0))
            trigger_state = int(t_data.get('state', 0)) # 🌟 CAPTURA SE A TRIGGER ESTÁ VERMELHA
            host_status = int(t_data.get('hosts', [{}])[0].get('status', 0)) if t_data.get('hosts') else 0
            
            # 🌟 DATA DE CORTE: 20 de Agosto de 2026 (Evita buscar lixo antigo)
            from datetime import datetime
            corte_data_nova = datetime(2026, 8, 20).timestamp()
            event_clock = int(p.get('clock', 0))

            # 🌟 1. IGNORA TRIGGERS E HOSTS DESATIVADOS DE PROPÓSITO (STATUS = 1)
            if trigger_status == 1 or host_status == 1:
                continue

            # 🌟 2. SE A FÓRMULA ESTIVER QUEBRADA (STATE = 1), SÓ IGNORA SE FOR ANTIGO
            if trigger_state == 1 and event_clock < corte_data_nova:
                continue

            # 🌟 3. VALIDAÇÃO DOS ITENS
            items = t_data.get('items', [])
            item_invalido = False
            if items:
                for it in items:
                    # Item desligado de propósito? Ignora sempre.
                    if int(it.get('status', 0)) == 1:
                        item_invalido = True
                        break
                    # Item 'unsupported' (quebrado)? Só ignora se o alerta for antigo.
                    if int(it.get('state', 0)) == 1 and event_clock < corte_data_nova:
                        item_invalido = True
                        break

            if item_invalido:
                continue
            
            p['atlas_host'] = t_data['hosts'][0]['name'] if t_data.get('hosts') else "Desconhecido"
            groups = t_data.get('groups', [])
            p['atlas_groups'] = sorted([g['name'] for g in groups]) if groups else ["Geral"]
            
            # --- CORREÇÃO DO OPDATA (DADOS OPERACIONAIS) ---
            op_data = p.get('opdata', '')
            if op_data: 
                p['atlas_opdata'] = op_data
            else:
                # O Zabbix nativo mostra o lastvalue se o OpData estiver vazio. Vamos imitar!
                items = t_data.get('items', [])
                if items:
                    op_parts = []
                    for it in items:
                        val = it.get('lastvalue')
                        if val:
                            unit = it.get('units', '')
                            # Junta o valor com a unidade, ex: "46.81 %"
                            op_parts.append(f"{val} {unit}".strip())
                    p['atlas_opdata'] = " | ".join(op_parts) if op_parts else ""
                else:
                    p['atlas_opdata'] = ""
            # -----------------------------------------------

            # 🛡️ LEITURA DE COMENTÁRIOS (Apenas Acks normais, ignorando Jarvis/Webhooks)
            acks = p.get('acknowledges', []) or []
            
            timeline = []
            for a in acks:
                timeline.append({'clock': int(a['clock']), 'msg': a.get('message', '')})
                
            if timeline:
                timeline = sorted(timeline, key=lambda x: x['clock'], reverse=True)
                latest_msg = timeline[0]['msg']
                
                # Mantém apenas a proteção do Atlas Bot
                tem_bot = any("[atlas bot]" in t['msg'].lower() for t in timeline)
                if tem_bot and "[ATLAS BOT]" not in latest_msg:
                    p['atlas_last_msg'] = f"[ATLAS BOT] Reconhecido. | {latest_msg}"
                else:
                    p['atlas_last_msg'] = latest_msg
            else:
                p['atlas_last_msg'] = ""
                
            final_data.append(p)
            
        return final_data
    
    def interact(self, event_ids, msg, action_type=6, user_token=None):
        if isinstance(event_ids, str): event_ids = [event_ids]
        return self._post("event.acknowledge", {"eventids": event_ids, "action": action_type, "message": msg}, token=user_token)

# Instância Global Padrão (Legado)
zabbix_api = ZabbixBridge()

def get_zabbix_connection(source_name):
    """
    Roteador Inteligente: Devolve a conexão certa baseada na origem do alerta.
    Se não achar ou for a origem padrão, retorna a conexão V4 (zabbix_api) intacta.
    """
    if not source_name or source_name == 'global':
        return zabbix_api # Usa o V4 padrão
    
    from models import TeamZabbixConfig
    config = TeamZabbixConfig.query.filter_by(team_name=source_name).first()
    
    if config and config.zabbix_url:
        return ZabbixBridge(
            front_url=config.zabbix_url, 
            user=config.api_user, 
            password=_get_decrypted_zabbix_pass(config.api_password)
        )
    
    return zabbix_api # Fallback de segurança para o V4

# ==============================================================================
# ROTAS FLASK
# ==============================================================================

@zabbix_bp.route('/zabbix')
@login_required
def zabbix_dashboard():
    if not current_user.can('can_access_zabbix'): return redirect(url_for('index'))
    return render_template('zabbix_dashboard.html', user=current_user)

@zabbix_bp.route('/admin/zabbix/vinculos', methods=['GET'])
@login_required
def admin_zabbix_vinculos():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('q', '').strip()
    
    # 🚀 OTIMIZAÇÃO: Carrega todos os relacionamentos em 1 única query (JOIN)
    query = ZabbixAlert.query.options(
        joinedload(ZabbixAlert.cliente_vinculado),
        joinedload(ZabbixAlert.procedimento_vinculado),
        joinedload(ZabbixAlert.cenario_vinculado),
        joinedload(ZabbixAlert.equipe_vinculada)
    ).order_by(ZabbixAlert.host.asc())
    
    if search:
        term = f"%{search}%"
        # Adicionei busca pelo nome do procedimento também
        query = query.filter(or_(
            ZabbixAlert.host.ilike(term), 
            ZabbixAlert.name.ilike(term), 
            ZabbixAlert.cliente_vinculado.has(ClienteChamado.nome.ilike(term)),
            ZabbixAlert.procedimento_vinculado.has(Procedimento.titulo.ilike(term)) # Busca por doc
        ))
        
    pagination = query.paginate(page=page, per_page=20, error_out=False)
    
    # [NOVO] Busca todos os procedimentos para o Dropdown
    procedimentos = Procedimento.query.order_by(Procedimento.titulo).all()

    return render_template('admin_zabbix_vinculos.html', 
                           alertas=pagination.items, 
                           pagination=pagination, 
                           clientes=ClienteChamado.query.all(), 
                           equipes=EquipeFrase.query.all(), 
                           cenarios=ClassificacaoChamado.query.all(),
                           procedimentos=procedimentos, # Enviando para o template
                           search_term=search)

@zabbix_bp.route('/admin/zabbix/exportar', methods=['GET'])
@login_required
def admin_zabbix_exportar():
    try:
        search = request.args.get('q', '').strip()
        
        # 🚀 OTIMIZAÇÃO: Impede que o Excel trave o banco com milhares de queries N+1
        query = ZabbixAlert.query.options(
            joinedload(ZabbixAlert.cliente_vinculado),
            joinedload(ZabbixAlert.equipe_vinculada)
        ).order_by(ZabbixAlert.host.asc())
        if search:
            term = f"%{search}%"
            query = query.filter(or_(ZabbixAlert.host.ilike(term), ZabbixAlert.name.ilike(term), ZabbixAlert.cliente_vinculado.has(ClienteChamado.nome.ilike(term))))
        data = []
        for d in query.all():
            data.append({
                "Host": d.host, "Trigger": d.name, 
                "Cliente": d.cliente_vinculado.nome if d.cliente_vinculado else "-", 
                "Equipe": d.equipe_vinculada.nome if d.equipe_vinculada else "-"
            })
        df = pd.DataFrame(data)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer: df.to_excel(writer, index=False)
        output.seek(0)
        return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', as_attachment=True, download_name=f"Vinculos_{datetime.now().strftime('%Y%m%d')}.xlsx")
    except Exception as e: return f"Erro: {e}", 500

@zabbix_bp.route('/api/zabbix/auth', methods=['POST'])
@login_required
def api_zabbix_auth():
    data = request.json
    user = data.get('user')
    password = data.get('password')

    token = zabbix_api.user_auth(user, password)
    if not token:
        return jsonify({"success": False, "error": "Login falhou"}), 401

    session['zbx_user_token'] = token
    tokens_map = {'global': token}

    # 👇 BLINDAGEM MULTI-TENANT 👇
    is_admin = getattr(current_user.role, 'name', '') == 'master_admin'
    user_teams = [t.strip().lower() for t in (current_user.teams or '').split(',')] if current_user.teams else []

    from models import TeamZabbixConfig
    for tc in TeamZabbixConfig.query.all():
        if tc.zabbix_url:
            # Se não for admin, pula os Zabbix que não são da equipa do utilizador
            if not is_admin and tc.team_name.lower() not in user_teams:
                continue
                
            bridge = ZabbixBridge(
                front_url=tc.zabbix_url, 
                user=tc.api_user, 
                password=_get_decrypted_zabbix_pass(tc.api_password)
            )
            try:
                tk = bridge.user_auth(user, password)
                if tk:
                    tokens_map[tc.team_name] = tk
                else:
                    logger.warning(f"[AUTH] Login pessoal falhou em {tc.team_name} (credenciais divergentes ou servidor fora do ar).")
            except Exception as e:
                logger.error(f"Falha ao logar utilizador no Zabbix {tc.team_name}: {e}")

    session['zbx_user_tokens'] = tokens_map
    session['zbx_user_login'] = user
    session.permanent = True
    return jsonify({"success": True})

@zabbix_bp.route('/api/zabbix/check_auth')
@login_required
def api_zabbix_check_auth(): 
    tokens_map = session.get('zbx_user_tokens', {})
    token_global = session.get('zbx_user_token')
    if token_global and 'global' not in tokens_map:
        tokens_map['global'] = token_global

    # 👇 BLINDAGEM MULTI-TENANT 👇
    is_admin = getattr(current_user.role, 'name', '') == 'master_admin'
    user_teams = [t.strip().lower() for t in (current_user.teams or '').split(',')] if current_user.teams else []

    # Descobre quais instâncias estão ativas e se temos token pra elas
    from models import TeamZabbixConfig
    active_sources = ['global']
    for tc in TeamZabbixConfig.query.all():
        if tc.zabbix_url:
            # Se não for admin, ignora a cobrança de token para instâncias de terceiros
            if not is_admin and tc.team_name.lower() not in user_teams:
                continue
            active_sources.append(tc.team_name)

    missing = []
    for source in active_sources:
        if source not in tokens_map or not tokens_map[source]:
            missing.append(source)
    
    return jsonify({
        "authenticated": len(missing) == 0,
        "missing_sources": missing
    })

@zabbix_bp.route('/api/zabbix/keepalive', methods=['POST'])
@login_required
def api_zabbix_keepalive():
    # 🌟 MÁGICA: Captura a mochila com TODOS os tokens do analista
    tokens_map = session.get('zbx_user_tokens', {})
    token_global = session.get('zbx_user_token')
    
    if not tokens_map and not token_global: 
        return jsonify({"status": "no_session"})
        
    # Garante que o global está na lista de verificação
    if token_global and 'global' not in tokens_map:
        tokens_map['global'] = token_global

    expired = False
    
    try:
        # Pinga TODAS as instâncias para manter a sessão do técnico viva!
        for source, tk in tokens_map.items():
            bridge = get_zabbix_connection(source)
            res = bridge._post("user.get", {"countOutput": True}, token=tk)
            
            # Se QUALQUER Zabbix responder que o token expirou, marca para reautenticar
            if res is not None and 'error' in res and 'Not authorized' in str(res['error']):
                expired = True
                break
                
        if expired:
            session.pop('zbx_user_token', None)
            session.pop('zbx_user_tokens', None)
            return jsonify({"status": "expired"})
            
        return jsonify({"status": "ok"})
    except:
        return jsonify({"status": "network_delay"})

import time

@zabbix_bp.route('/api/zabbix/latency', methods=['GET'])
@login_required
def api_zabbix_latency():
    """Mede a latência (ms) entre o Atlas e a API do Zabbix"""
    start_time = time.time()
    try:
        # apiinfo.version é a requisição mais leve do Zabbix (não pesa no banco deles)
        res = zabbix_api._post("apiinfo.version", {})
        end_time = time.time()
        
        latency_ms = int((end_time - start_time) * 1000)
        
        # Define a saúde da conexão
        status = "good"
        if latency_ms > 800:
            status = "warning" # Zabbix demorando quase 1 segundo
        if latency_ms > 3000:
            status = "bad"     # Zabbix engasgado (mais de 3s)
            
        return jsonify({"status": status, "ms": latency_ms})
    except Exception as e:
        return jsonify({"status": "offline", "ms": 0, "error": str(e)})

@zabbix_bp.route('/api/zabbix/groups')
@login_required
def api_zabbix_groups():
    resultado = []
    
    # 1. Zabbix Global (V4)
    try:
        grupos_v4 = sorted([g['name'] for g in zabbix_api.get_all_hostgroups()])
        if grupos_v4:
            resultado.append({
                "id_source": "global",
                "title": "Zabbix Global (Legado)",
                "version": "V4",
                "groups": grupos_v4
            })
    except Exception as e:
        logger.warning(f"Erro ao buscar grupos do Zabbix Global: {e}")

    # 2. Multi-Zabbix por Equipe (V7)
    from models import TeamZabbixConfig
    configs = TeamZabbixConfig.query.all()
    
    # 👇 BLINDAGEM MULTI-TENANT 👇
    is_admin = getattr(current_user.role, 'name', '') == 'master_admin'
    user_teams = [t.strip().lower() for t in (current_user.teams or '').split(',')] if current_user.teams else []
    
    for config in configs:
        if not config.zabbix_url: continue
        
        # Pula a busca de grupos se o Zabbix não pertencer ao utilizador
        if not is_admin and config.team_name.lower() not in user_teams:
            continue
            
        try:
            # 🛡️ CIRCUIT BREAKER: Testa se a URL responde em até 3 segundos antes de travar o servidor
            try:
                requests.get(config.zabbix_url, timeout=3, verify=False)
            except requests.exceptions.RequestException:
                logger.warning(f"Zabbix {config.team_name} inatingível (Timeout).")
                # Envia pro frontend avisando que está offline!
                resultado.append({
                    "id_source": config.team_name,
                    "title": f"Zabbix {config.team_name} (OFFLINE)",
                    "version": "V7",
                    "groups": []
                })
                continue

            # Se respondeu rápido, faz o login e busca os grupos
            bridge_v7 = ZabbixBridge(
                front_url=config.zabbix_url, 
                user=config.api_user, 
                password=_get_decrypted_zabbix_pass(config.api_password)
            )
            
            grupos_v7 = sorted([g['name'] for g in bridge_v7.get_all_hostgroups()])
            
            # 🚀 FIX: Filtra os grupos da instância caso exista uma whitelist_groups cadastrada
            whitelist = str(getattr(config, 'whitelist_groups', '') or '').strip()
            if whitelist:
                allowed_wh = [w.strip() for w in whitelist.split(',') if w.strip()]
                grupos_v7 = [g for g in grupos_v7 if g in allowed_wh]

            resultado.append({
                "id_source": config.team_name,
                "title": f"Zabbix {config.team_name}",
                "version": "V7",
                "groups": grupos_v7
            })
            
        except Exception as e:
            logger.warning(f"Erro ao buscar grupos do Zabbix V7 ({config.team_name}): {e}")

    return jsonify(resultado)

# ==============================================================================
# ROTA PRINCIPAL: API DE ALERTAS (COM TRAVA E LÓGICA DE RESPEITO)
# ==============================================================================
@zabbix_bp.route('/api/zabbix/alerts')
@login_required
def api_zabbix_alerts():
    # Pega o timestamp enviado pelo Frontend (se não vier, pega do zero)
    since_ts = request.args.get('since', 0, type=float)
    # Passamos o since_ts para a função buscar apenas os deltas
    return jsonify(get_alerts_json(current_user.id, since_ts))

@zabbix_bp.route('/api/zabbix/vincular', methods=['POST'])
@login_required
def api_zabbix_vincular():
    if not current_user.can('can_manage_zabbix_config'): return jsonify({"success": False}), 403
    d = request.json
    a = ZabbixAlert.query.get(d.get('alerta_id'))
    if a:
        # 1. Atualiza Cliente, Cenário e Equipe baseado no HOST
        ZabbixAlert.query.filter_by(host=a.host).update({
            'cliente_id_manual': d.get('cliente_id') or None, 
            'cenario_id_manual': d.get('cenario_id') or None,
            'equipe_id_manual': d.get('equipe_id') or None
        })
        
        # 2. Atualiza o POP/Procedimento baseado no NOME DA TRIGGER (Correto)
        if d.get('procedimento_id'):
            ZabbixAlert.query.filter_by(name=a.name).update({
                'procedimento_id_manual': d.get('procedimento_id')
            })
            
        # 🌟 BLINDAGEM DE TRANSAÇÃO (ANTI-CONEXÃO PRESA)
        try:
            db.session.commit()
            return jsonify({"success": True})
        except Exception as e:
            db.session.rollback()
            logger.error(f"🔥 Erro ao comitar transação em vincular: {e}")
            return jsonify({"success": False, "error": f"Erro de banco de dados: {str(e)}"}), 500
            
    return jsonify({"success": False}), 404

# Se True, ao fechar um card o servidor também fecha irmãos ativos (mesmo trigger+host+origem+dono) que o
# navegador NÃO enviou no payload. DESLIGADO por padrão: o analista só fecha o que viu; um evento novo
# que chegar no banco reaparece como card visível em vez de ser fechado sem ninguém ter visto.
FECHAR_IRMAOS_NAO_VISTOS = False


def _parse_pares(raw):
    """Normaliza o payload do front em pares (eventid, source_zabbix).
    Aceita dicts {id, source} e, por legado, ids soltos (assumidos como 'global').
    """
    raw_list = raw if isinstance(raw, list) else [raw]
    pares = []
    vistos = set()
    for item in raw_list:
        if isinstance(item, dict):
            eid, src = item.get('id'), (item.get('source') or 'global')
        elif isinstance(item, (str, int)):
            eid, src = item, 'global'
        else:
            continue
        if eid in (None, ''):
            continue
        par = (str(eid), str(src))
        if par not in vistos:
            vistos.add(par)
            pares.append(par)
    return pares


@zabbix_bp.route('/api/zabbix/interact', methods=['POST'])
@login_required
def api_zabbix_interact():
    from sqlalchemy import tuple_
    
    token = session.get('zbx_user_token')
    if not token: 
        return jsonify({"success": False, "error": "AUTH_REQUIRED"}), 401
    
    d = request.json
    raw = d.get('event_ids') or d.get('event_id')
    pares = _parse_pares(raw)

    if not pares:
        return jsonify({"success": True})
        
    alerts = ZabbixAlert.query.filter(
        tuple_(ZabbixAlert.eventid, ZabbixAlert.source_zabbix).in_(pares)
    ).all()
    matched_pedidos = len(alerts)

    # 🛡️ ANTI-ZUMBI: o front manda um snapshot (all_event_ids). Irmãos criados DEPOIS dessa foto
    # não estariam no payload e reapareceriam. Para 'close', o servidor completa a lista com os
    # irmãos que o front esconde na deduplicação: mesmo objectid + host + origem, sev 5, ativos e
    # com o MESMO dono (o dedup do front só agrupa alertas já assumidos, com mesmo owner).
    expandidos = 0
    if FECHAR_IRMAOS_NAO_VISTOS and d.get('action') == 'close' and d.get('source', 'dash') != 'mon' and alerts:
        def _dono(v):
            v = '' if v is None else str(v).strip()
            return '' if v in ('', 'None') else v

        chaves = {}
        for a0 in alerts:
            if a0.status == 'active' and a0.severity == 5 and a0.objectid and _dono(a0.ack_user_id):
                chaves[(a0.objectid, a0.host, a0.source_zabbix)] = _dono(a0.ack_user_id)

        if chaves:
            ja_incluidos = {(x.eventid, x.source_zabbix) for x in alerts}
            candidatos = ZabbixAlert.query.filter(
                ZabbixAlert.status == 'active',
                ZabbixAlert.severity == 5,
                tuple_(ZabbixAlert.objectid, ZabbixAlert.host, ZabbixAlert.source_zabbix).in_(list(chaves.keys()))
            ).all()
            for c0 in candidatos:
                if (c0.eventid, c0.source_zabbix) in ja_incluidos:
                    continue
                if _dono(c0.ack_user_id) == chaves.get((c0.objectid, c0.host, c0.source_zabbix)):
                    alerts.append(c0)
                    expandidos += 1

    alerts.sort(key=lambda x: int(x.eventid)) 
    
    # --- 🌟 TRAVA ANTI-ATLAS: Exige token específico e avisa quem faltou ---
    tokens_map = session.get('zbx_user_tokens', {})
    token_global = session.get('zbx_user_token')
    if token_global and 'global' not in tokens_map:
        tokens_map['global'] = token_global

    for a in alerts:
        source = a.source_zabbix or 'global'
        if source not in tokens_map or not tokens_map[source]:
            return jsonify({"success": False, "error": "AUTH_REQUIRED", "missing_sources": [source]}), 401
    # -----------------------------------------------------------------------
        
    raw_msg = d.get('message', '').strip()
    custom_msg = raw_msg[:250] + "..." if len(raw_msg) > 250 else raw_msg
    
    source = d.get('source', 'dash') 
    
    act_zbx = 6  # Padrão é 6 (Acknowledge + Message)
    msg_zbx = custom_msg
    call_zbx = False 

    processados = []
    for a in alerts:
        # Guard de idempotência: evita recadastrar dados em alertas já fechados
        if a.status == 'resolved_manual' and d['action'] in ['close', 'take', 'unassign']:
            continue
        processados.append(a)
            
        a.last_seen = datetime.now() # 🌟 MÁGICA: Atualiza pro Frontend sempre puxar na hora!
        
        if d['action'] == 'take':
            # 🧩 Grupo manual é curadoria do dono anterior: ao roubar de outro, sai do grupo dele
            if a.ack_user_id and str(a.ack_user_id) != str(current_user.id):
                a.manual_group_id = None
            a.ack_user_id = current_user.id
            final_msg = custom_msg if custom_msg else "Em Atendimento"
            a.ack_message = final_msg
            a.ack_at = datetime.now() 
            a.hidden_on_dash = False 
            act_zbx = 6  # 🌟 Tem que ser 6
            msg_zbx = final_msg
            call_zbx = True

        elif d['action'] == 'comment':
            if a.ack_user_id and str(a.ack_user_id) != str(current_user.id):
                a.manual_group_id = None
            a.ack_user_id = current_user.id
            a.ack_message = custom_msg
            act_zbx = 6  # 🌟 Tem que ser 6
            msg_zbx = custom_msg
            call_zbx = True

        elif d['action'] == 'unassign':
            a.ack_user_id = None
            a.manual_group_id = None  # 🧩 volta pra fila avulso
            a.ack_message = ""
            a.hidden_on_dash = False
            act_zbx = 6
            msg_zbx = custom_msg if custom_msg else "Alerta desvinculado e retornado para a fila."
            call_zbx = True

        elif d['action'] == 'close':
            a.ack_user_id = current_user.id
            a.manual_group_id = None  # 🌟 Desvincula do grupo manual ao concluir
            act_zbx = 6
            msg_zbx = custom_msg

            if source == 'mon':
                a.status = 'resolved_manual'
                a.resolved_at = datetime.now()
                act_zbx = 1 
                msg_zbx = custom_msg if custom_msg else "Finalizado via Atlas MON"
                call_zbx = True 
                
                chamado_existente = Noticia.query.filter(Noticia.zabbix_url.ilike(f"%eventid={a.eventid}%")).first()
                if not chamado_existente:
                    user_team = current_user.teams.split(',')[0].strip() if current_user.teams else 'Geral'
                    texto_resolucao = f"<b>Alerta encerrado via Painel MON.</b><br><br><b>Host:</b> {a.host}<br><b>Incidente:</b> {a.name}<br>"
                    if a.description: texto_resolucao += f"<b>OpData:</b> {a.description}<br>"
                    if custom_msg: texto_resolucao += f"<br><b>Observação:</b> {custom_msg}"
                    
                    from models import TeamZabbixConfig # Importação de segurança
                    urls_motores = {tc.team_name: tc.zabbix_url.rstrip('/') for tc in TeamZabbixConfig.query.all() if tc.zabbix_url}
                    base_url_zabbix = urls_motores.get(a.source_zabbix, ZABBIX_FRONT_URL)
                    
                    novo_registro = Noticia(
                        titulo=f"[Interno] MON/HADES - {a.host}",
                        resumo="Monitoramento Ativo",
                        conteudo=texto_resolucao,
                        tag="Monitoramento",
                        equipe=user_team,
                        zabbix_url=f"{base_url_zabbix}/tr_events.php?triggerid={a.objectid}&eventid={a.eventid}",
                        status_problema='Resolvido',
                        autor_id=current_user.id,
                        responsavel_id=current_user.id,
                        data_criacao=a.start_time,
                        data_assuncao=a.start_time,
                        data_resolucao=a.resolved_at,
                        resolucao=custom_msg if custom_msg else "Finalizado via Painel MON"
                    )
                    db.session.add(novo_registro)
            else:
                a.hidden_on_dash = True
                a.status = 'resolved_manual'
                a.resolved_at = datetime.now()
                
                # Oculta estritamente o evento clicado, preservando novas reincidências e respeitando a origem
                ZabbixAlert.query.filter_by(eventid=a.eventid, source_zabbix=a.source_zabbix).update({
                    'hidden_on_dash': True,
                    'status': 'resolved_manual',
                    'resolved_at': datetime.now()
                })
                call_zbx = False

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    
    from collections import defaultdict
    alertas_por_source = defaultdict(list)
    for a in processados:
        alertas_por_source[a.source_zabbix or 'global'].append(a.eventid)

    if call_zbx and alertas_por_source:
        from tasks import bg_zabbix_call_task
        # ❌ Linha removida: tokens_map já foi montado de forma segura no início da rota!
        try:
            bg_zabbix_call_task.delay(dict(alertas_por_source), msg_zbx, act_zbx, tokens_map)
        except Exception as celery_err:
            logger.error(f"⚠️ Celery indisponível: {celery_err}")
            
    # matched = quantos pares existem no banco; changed = quantos foram de fato alterados
    # (permite ao front detectar no-op silencioso, ex.: origem errada no payload)
    return jsonify({
        "success": True,
        "requested": len(pares),
        "matched": matched_pedidos,
        "expanded": expandidos,
        "changed": len(processados)
    })


@zabbix_bp.route('/api/zabbix/event_history/<event_id>')
@login_required
def api_zabbix_event_history(event_id):
    """Busca a linha do tempo de comentários (Acks) e Ações de Status (Alerts) do Zabbix"""
    try:
        if str(event_id).startswith('mass_'):
            return jsonify({"success": True, "comments": [{"time": "", "user": "Atlas", "message": "Alertas agrupados. Acesse o histórico individual na lista de filhos."}]})

        alert = ZabbixAlert.query.filter_by(eventid=event_id).first()
        source = alert.source_zabbix if alert else 'global'
        bridge = get_zabbix_connection(source)

        # 1. MÁGICA AQUI: Puxamos "select_acknowledges" E "selectAlerts" ao mesmo tempo!
        params = {"eventids": [event_id], "select_acknowledges": "extend", "selectAlerts": "extend"}
        res_evt = bridge._post("event.get", params)
        
        if res_evt is None:
            return jsonify({"success": False, "error": "Timeout na comunicação com o Zabbix ao buscar histórico."})
        
        # Fallback de sintaxe para algumas versões do Zabbix
        if 'error' in res_evt and 'select_acknowledges' in str(res_evt.get('error', '')):
            del params['select_acknowledges']
            params['selectAcknowledges'] = "extend"
            res_evt = bridge._post("event.get", params)
            
        resultado_zabbix = res_evt['result'][0] if res_evt.get('result') else {}
        
        # Separa os Comentários das Ações (Status)
        acks = resultado_zabbix.get('acknowledges', [])
        alerts_actions = resultado_zabbix.get('alerts', [])
        
        user_ids = list(set([str(a.get('userid')) for a in acks if a.get('userid') and str(a.get('userid')) != "0"]))
        
        users_map = {}
        if user_ids:
            u_res = bridge._post("user.get", {"userids": user_ids, "output": ["userid", "username", "name", "surname", "alias"]})
            for u in u_res.get('result', []):
                alias = u.get('username', u.get('alias', ''))
                nome = f"{u.get('name', '')} {u.get('surname', '')}".strip()
                users_map[str(u['userid'])] = nome if nome else alias

        comments = []
        
        # --- PROCESSA OS COMENTÁRIOS NORMAIS ---
        for ack in acks:
            if not ack.get('message'): continue
            dt = datetime.fromtimestamp(int(ack['clock'])).strftime('%d/%m %H:%M')
            
            user_alias = ack.get('username', ack.get('alias', ''))
            if not user_alias: user_alias = users_map.get(str(ack.get('userid')), '')
            if not user_alias:
                msg_lower = ack.get('message', '').lower()
                if 'atendimento' in msg_lower or 'auto-assign' in msg_lower: user_alias = 'Atlas NOC'
                else: user_alias = 'Sistema'
                
            comments.append({
                "clock": int(ack['clock']),
                "time": dt,
                "user": user_alias,
                "message": ack['message']
            })
            
        # --- PROCESSA AS AÇÕES E STATUS DO JARVIS (E-mails, Comandos Remotos, etc) ---
        for al in alerts_actions:
            dt = datetime.fromtimestamp(int(al['clock'])).strftime('%d/%m %H:%M')
            
            status_zbx = str(al.get('status'))
            action_type = str(al.get('actiontype')) # 0 = Mensagem/Notificação, 1 = Comando Remoto
            
            # Decodifica o Status que o Zabbix retorna como número
            if status_zbx == "1":
                status_text = "✅ Executado com sucesso" if action_type == "1" else "✅ Enviado"
            elif status_zbx == "2":
                status_text = f"❌ Falha: {al.get('error', 'Erro interno no Zabbix')}"
            else:
                status_text = "⏳ Em andamento..."

            acao_nome = "Comando Remoto" if action_type == "1" else "Notificação/Ação"
            subject = al.get('subject', '')
            
            # Formata como se fosse um comentário para a A.I.D.A. ler bonitinho
            if subject:
                mensagem_montada = f"[Jarvis] {acao_nome} disparado: {subject} \nStatus da Execução: {status_text}"
            else:
                mensagem_montada = f"[Jarvis] {acao_nome} disparado. \nStatus da Execução: {status_text}"

            comments.append({
                "clock": int(al['clock']),
                "time": dt,
                "user": "Jarvis AI (Ações)",
                "message": mensagem_montada
            })

        # Organiza tudo misturado, do mais novo pro mais velho
        comments.sort(key=lambda x: x['clock'], reverse=True)
        return jsonify({"success": True, "comments": comments})
        
    except Exception as e:
        print(f"⚠️ Erro ao buscar histórico: {e}", flush=True)
        return jsonify({"success": False, "error": str(e)})


# ==============================================================================
# HELPER: DESENHAR A LINHA DO ZABBIX (Versão High Quality + Visual Ajustado)
# ==============================================================================
def _create_zabbix_row_image(data):
    """Gera uma imagem simulando o visual da lista de problemas do Zabbix (Dark)."""
    try:
        # Configurações do Layout (Reduzido para 1100px pois removemos colunas)
        WIDTH, HEIGHT = 1100, 80 
        BG_COLOR = (31, 31, 31)       # #1f1f1f
        HEADER_BG = (43, 43, 43)      # #2b2b2b
        TEXT_COLOR = (242, 242, 242)  # Branco
        LINK_COLOR = (0, 136, 204)    # Azul link
        
        # Mapeamento de Severidade
        SEV_COLORS = {
            0: (151, 170, 179), # Not Classified
            1: (116, 153, 255), # Info
            2: (255, 200, 89),  # Warning
            3: (255, 160, 89),  # Average
            4: (233, 118, 89),  # High
            5: (228, 89, 89)    # Disaster
        }
        
        sev_id = int(data.get('severity', 0))
        sev_color = SEV_COLORS.get(sev_id, (128, 128, 128))
        
        sev_names = {
    0: 'Nao classificado', 
    1: 'Informacao', 
    2: 'Atencao', 
    3: 'Media', 
    4: 'Alta', 
    5: 'Critico' 
}
        sev_text = sev_names.get(sev_id, 'Desconhecido')
        
        start_dt = datetime.fromtimestamp(int(data['clock']))
        time_str = start_dt.strftime('%H:%M:%S')
        
        # Cria Imagem
        img = Image.new('RGB', (WIDTH, HEIGHT), color=BG_COLOR)
        draw = ImageDraw.Draw(img)
        
        # --- CARREGAMENTO DE FONTES (ROBUSTO) ---
        font_main = None
        font_small = None
        
        # Lista de fontes possíveis no Linux (Liberation e DejaVu são comuns)
        paths_to_try = [
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf"
        ]
        
        for path in paths_to_try:
            try:
                font_main = ImageFont.truetype(path, 13)
                font_small = ImageFont.truetype(path.replace("Bold", "Regular"), 12)
                break
            except: continue
            
        if not font_main: # Fallback
            font_main = ImageFont.load_default()
            font_small = font_main

        # 1. Desenhar Cabeçalho
        draw.rectangle([(0, 0), (WIDTH, 30)], fill=HEADER_BG)
        # Colunas: Hora | Severidade | Status | Host | Incidente
        cols_x = [10, 90, 210, 320, 650]
        headers = ["Hora", "Severidade", "Status", "Host", "Incidente"]
        
        for i, h_text in enumerate(headers):
            draw.text((cols_x[i], 8), h_text, font=font_small, fill=(150, 150, 150)) 

        # 2. Desenhar Dados da Linha (y=45)
        row_y = 45
        
        # Hora
        draw.text((cols_x[0], row_y), time_str, font=font_main, fill=LINK_COLOR)
        
        # Severidade (Caixa Colorida + Texto Centralizado)
        sev_w = 100
        sev_h = 20 # Um pouco mais alto para acomodar melhor
        sev_rect_y = row_y - 3
        draw.rectangle([(cols_x[1], sev_rect_y), (cols_x[1]+sev_w, sev_rect_y+sev_h)], fill=sev_color)
        
        text_to_draw = sev_text.upper()
        # Cálculo de centralização
        bbox = draw.textbbox((0, 0), text_to_draw, font=font_small)
        t_width = bbox[2] - bbox[0]
        t_x = cols_x[1] + (sev_w - t_width) / 2
        
        # Cor do texto: preto em cores claras, branco em cores escuras
        t_color = (0,0,0) if sev_id in [0, 2] else (255,255,255)
        draw.text((t_x, row_y), text_to_draw, font=font_small, fill=t_color)
        
        # Status Híbrido (Trata strings, inteiros e valores nulos/None com segurança)
        is_resolved = data.get('r_eventid') and str(data.get('r_eventid')) != "0"
        
        status_txt = "RESOLVIDO" if is_resolved else "INCIDENTE"
        status_col = (35, 213, 69) if status_txt == "RESOLVIDO" else (228, 89, 89)
        draw.text((cols_x[2], row_y), status_txt, font=font_main, fill=status_col)
        
        # Host (Truncado)
        host_txt = data.get('atlas_host', 'N/A')
        draw.text((cols_x[3], row_y), host_txt[:45], font=font_main, fill=TEXT_COLOR) 
        
        # Incidente (Truncado)
        prob_txt = data.get('name', '-')
        max_chars = 70 
        display_prob = prob_txt[:max_chars] + ('...' if len(prob_txt)>max_chars else '')
        draw.text((cols_x[4], row_y), display_prob, font=font_main, fill=TEXT_COLOR)

        # Salva em memória
        buf = BytesIO()
        img.save(buf, format='PNG')
        return buf.getvalue()

    except Exception as e:
        logger.error(f"Erro ao desenhar linha Zabbix: {e}")
        return None

def _get_zabbix_image_bytes(session_requests, item_id, start_clock, time_from, time_till, width=800, height=200):
    # Fix para Zabbix 4.4 (stime + period)
    period = int(time_till - time_from)
    stime = int(time_from)
    
    # REMOVI O "name=Atlas&" DA STRING ABAIXO. 
    # Agora o Zabbix vai usar o nome real do item (ex: "Utilização de CPU") como título.
    url = f"{zabbix_api.front_url}/chart3.php?items[0][itemid]={item_id}&items[0][drawtype]=5&width={width}&height={height}&stime={stime}&period={period}"    
    # Colocamos 15s de leitura pois baixar imagem é mais pesado que texto
    r = session_requests.get(url, timeout=(3.0, 15.0))
    return r.content if r.status_code == 200 else None

def _get_trigger_item_id(event_id):
    # BLINDAGEM: Não podemos mandar "mass_" pra API do zabbix 
    if str(event_id).startswith('mass_'):
        return None, None
        
    ed = zabbix_api._post("event.get", {"eventids": event_id, "output": ["objectid", "clock"]})
    if not ed.get('result'): return None, None
    e = ed['result'][0]
    td = zabbix_api._post("trigger.get", {"triggerids": e['objectid'], "selectFunctions": ["itemid"]})
    if not td.get('result'): return None, None
    fs = td['result'][0].get('functions', [])
    if not fs: return None, None
    return fs[0]['itemid'], int(e['clock'])

@zabbix_bp.route('/api/zabbix/graphs_preview/<event_id>')
@login_required
def api_zabbix_graphs_preview(event_id):
    try:
        # Se for MASS_ alerta os metadados são recusados pelo preview do Dashboard
        # Rejeita na triagem
        if str(event_id).startswith('mass_'):
            return jsonify({"success": False, "error": "Alertas agrupados não tem histórico. Expança o grupo."}), 500
            
        # 1. Prepara dados para o Gráfico de Histórico (Original)
        iid, start = _get_trigger_item_id(event_id)
        
        # 2. NOVO: Prepara dados para o "Print" (Snapshot da linha)
        details = zabbix_api.get_enriched_problems(specific_ids=[event_id])
        data_row = details[0] if details else {}
        
        # Gera a imagem do "Print" (Snapshot) e converte para Base64
        b_row_img = _create_zabbix_row_image(data_row)
        str_zoom = ""
        if b_row_img:
            str_zoom = f"data:image/png;base64,{base64.b64encode(b_row_img).decode()}"

        # Gera a imagem do Gráfico (Histórico) - Lógica original mantida
        str_history = ""
        if iid:
            with requests.Session() as s:
                s.post(f"{zabbix_api.front_url}/index.php", data={"name": ZABBIX_MASTER_USER, "password": ZABBIX_MASTER_PASS, "enter": "Sign in", "autologin": 1}, timeout=(3.0, 10.0))
                h = _get_zabbix_image_bytes(s, iid, start, start-86400, start+3600)
                if h:
                    str_history = f"data:image/png;base64,{base64.b64encode(h).decode()}"

        # Retorna ambas as imagens para o Front-End
        if str_zoom or str_history:
            return jsonify({
                "success": True,
                "img_zoom": str_zoom,       # <--- Agora o modal vai receber esta imagem
                "img_history": str_history
            })
            
        return jsonify({"success": False, "error": "Nenhuma imagem gerada"}), 500

    except Exception as e:
        logger.error(f"Preview Error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500    

@zabbix_bp.route('/api/zabbix/download_zip/<event_id>')
@login_required
def api_zabbix_download_zip(event_id):
    try:
        event_ids_to_process = []
        
        # 1. Se for um alerta agrupado (mass_), resgata os IDs de todos os filhos
        if str(event_id).startswith('mass_'):
            dash_data = get_alerts_json(current_user.id)
            alerts_list = dash_data.get('alerts', []) if isinstance(dash_data, dict) else []
            parent_alert = next((a for a in alerts_list if str(a.get('id')) == str(event_id)), None)
            
            if parent_alert and parent_alert.get('child_ids'):
                event_ids_to_process = [str(cid) for cid in parent_alert['child_ids']]
            elif parent_alert and parent_alert.get('child_data'):
                event_ids_to_process = [str(c['id']) for c in parent_alert['child_data']]
        else:
            event_ids_to_process = [str(event_id)]

        if not event_ids_to_process:
            flash("Nenhum alerta encontrado no grupo para gerar evidências.", "danger")
            return redirect(url_for('zabbix.zabbix_dashboard'))

        # 🚀 Trava de Segurança: Limita a no máximo 10 alertas por ZIP para evitar timeout
        event_ids_to_process = event_ids_to_process[:10]

        mem = BytesIO()
        files_added = 0

        # Login único no Zabbix para reaproveitar a sessão de gráficos
        with requests.Session() as s:
            try:
                s.post(f"{zabbix_api.front_url}/index.php", data={
                    "name": ZABBIX_MASTER_USER, 
                    "password": ZABBIX_MASTER_PASS, 
                    "enter": "Sign in", 
                    "autologin": 1
                }, timeout=(3.0, 10.0))
            except Exception as e_login:
                logger.warning(f"Aviso de login Zabbix no ZIP: {e_login}")

            with zipfile.ZipFile(mem, 'w') as zf:
                for idx, eid in enumerate(event_ids_to_process, 1):
                    try:
                        # A) Snapshot da linha (Print de detalhes)
                        details = zabbix_api.get_enriched_problems(specific_ids=[eid])
                        data_row = details[0] if details else {}
                        if data_row:
                            b_row_img = _create_zabbix_row_image(data_row)
                            if b_row_img:
                                zf.writestr(f"item_{idx}_alerta_{eid}_snapshot.png", b_row_img)
                                files_added += 1

                        # B) Gráfico de histórico de 24h
                        iid, start = _get_trigger_item_id(eid)
                        if iid and start:
                            b_hist = _get_zabbix_image_bytes(s, iid, start, start - 86400, start + 3600)
                            if b_hist:
                                zf.writestr(f"item_{idx}_alerta_{eid}_grafico_24h.png", b_hist)
                                files_added += 1
                    except Exception as e_child:
                        logger.error(f"Erro ao processar evidência do alerta {eid}: {e_child}")

        if files_added == 0:
            flash("Não foi possível gerar nenhuma evidência para este grupo de alertas.", "danger")
            return redirect(url_for('zabbix.zabbix_dashboard'))

        mem.seek(0)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M')
        
        return send_file(
            mem, 
            mimetype='application/zip', 
            as_attachment=True, 
            download_name=f"Evidencias_Grupo_{event_id}_{timestamp}.zip"
        )

    except Exception as e:
        logger.error(f"ZIP Group Fatal Error: {e}")
        flash(f"Erro interno ao criar arquivo ZIP de evidências: {str(e)}", "danger")
        return redirect(url_for('zabbix.zabbix_dashboard'))
    
    # --- ADICIONE NO FINAL DO ARQUIVO zabbix_logic.py ---

from collections import Counter

@zabbix_bp.route('/zabbix/analytics')
@login_required
def zabbix_analytics_view():
    if not current_user.can('can_access_zabbix'): 
        return redirect(url_for('index'))
    return render_template('zabbix_stats.html', user=current_user)

from collections import Counter, defaultdict

# --- ARQUIVO: zabbix_logic.py ---

@zabbix_bp.route('/api/zabbix/stats/data', methods=['POST'])
@login_required
def api_zabbix_stats_data():
    try:
        filters = request.json or {}
        
        # 1. Datas (Padrão 7 dias)
        try:
            if filters.get('date_start') and filters.get('date_end'):
                dt_start = datetime.strptime(filters['date_start'], '%Y-%m-%d')
                dt_end = datetime.strptime(filters['date_end'], '%Y-%m-%d').replace(hour=23, minute=59, second=59)
            else:
                dt_end = datetime.now()
                dt_start = dt_end - timedelta(days=7) 
        except:
            dt_end = datetime.now()
            dt_start = dt_end - timedelta(days=7)

        # Filtros
        filter_hosts = filters.get('hosts', [])
        try:
            filter_sevs = [int(s) for s in filters.get('severities', ['4', '5'])]
        except:
            filter_sevs = [4, 5]

        # 2. Busca Problemas
        ts_from = int(dt_start.timestamp())
        ts_till = int(dt_end.timestamp())
        
        params = {
            "output": ["eventid", "objectid", "name", "clock", "severity", "acknowledged"], 
            "selectAcknowledges": "count",
            "time_from": ts_from,
            "time_till": ts_till,
            "severities": filter_sevs,
            "sortfield": ["eventid"], 
            "sortorder": "DESC",
            "limit": 5000 
        }
        
        zbx_resp = zabbix_api._post("problem.get", params)
        # 🛡️ PROTEÇÃO AQUI
        raw_problems = zbx_resp.get('result', []) if zbx_resp else []
        
        if not raw_problems:
            return jsonify({
                "kpis": {"total":0, "disaster":0, "high":0, "ack_percent":0, "unack_count":0},
                "charts": {"sev_series":[0,0], "timeline_dates":[], "timeline_values":[], "ack_series":[0,0], "hosts_data":[]},
                "meta": {"available_hosts": []}
            })

        # 3. Busca Hosts (CORREÇÃO DE NOME)
        trigger_ids = list(set(p['objectid'] for p in raw_problems if 'objectid' in p))
        host_map_local = {}
        
        chunk_size = 100
        for i in range(0, len(trigger_ids), chunk_size):
            chunk = trigger_ids[i:i + chunk_size]
            if not chunk: continue
            
            t_res = zabbix_api._post("trigger.get", {
                "triggerids": chunk,
                "output": ["triggerid"],
                "selectHosts": ["name", "host"] # Pega 'name' (Visível) e 'host' (Técnico)
            })
            
            for t in t_res.get('result', []):
                if t.get('hosts') and len(t['hosts']) > 0:
                    # Tenta pegar o nome visível primeiro, se não tiver, pega o técnico
                    host_obj = t['hosts'][0]
                    # Essa é a mesma lógica do Dashboard principal
                    host_map_local[t['triggerid']] = host_obj.get('name', host_obj.get('host', 'Desconhecido'))

        # 4. Processamento
        total_alerts = 0
        by_severity = {4: 0, 5: 0}
        ack_status = {"ack": 0, "unack": 0}
        hosts_stats = {} 
        timeline_data = defaultdict(int)
        
        delta = dt_end - dt_start
        for i in range(delta.days + 1):
            day = (dt_start + timedelta(days=i)).strftime('%d/%m')
            timeline_data[day] = 0

        for p in raw_problems:
            tid = p.get('objectid')
            h_name = host_map_local.get(tid, 'Host Desconhecido')
            
            if filter_hosts and h_name not in filter_hosts:
                continue

            total_alerts += 1
            sev = int(p['severity'])
            
            if sev in by_severity: by_severity[sev] += 1
            
            is_ack = int(p.get('acknowledged', 0))
            if is_ack == 1: ack_status["ack"] += 1
            else: ack_status["unack"] += 1
            
            ts = int(p['clock'])
            date_str = datetime.fromtimestamp(ts).strftime('%d/%m')
            if date_str in timeline_data: timeline_data[date_str] += 1
            
            if h_name not in hosts_stats:
                hosts_stats[h_name] = {"name": h_name, "total": 0, "crit": 0, "high": 0}
            
            hosts_stats[h_name]["total"] += 1
            if sev == 5: hosts_stats[h_name]["crit"] += 1
            elif sev == 4: hosts_stats[h_name]["high"] += 1

        sorted_timeline = sorted(timeline_data.items(), key=lambda x: datetime.strptime(x[0] + f"/{dt_end.year}", '%d/%m/%Y'))
        full_hosts_list = sorted(list(hosts_stats.values()), key=lambda x: x['total'], reverse=True)
        all_hosts_found = sorted(list(hosts_stats.keys()))

        return jsonify({
            "kpis": {
                "total": total_alerts,
                "disaster": by_severity[5],
                "high": by_severity[4],
                "ack_percent": round((ack_status["ack"] / total_alerts * 100), 1) if total_alerts > 0 else 0,
                "unack_count": ack_status["unack"]
            },
            "charts": {
                "sev_series": [by_severity[5], by_severity[4]], 
                "timeline_dates": [x[0] for x in sorted_timeline],
                "timeline_values": [x[1] for x in sorted_timeline],
                "ack_series": [ack_status["ack"], ack_status["unack"]],
                "hosts_data": full_hosts_list
            },
            "meta": { "available_hosts": all_hosts_found }
        })

    except Exception as e:
        logger.error(f"Stats Fatal Error: {e}")
        return jsonify({"error": str(e)}), 500
    
# --- ADICIONE ISSO NO FINAL DE zabbix_logic.py ---

# 1. ROTA DA TELA (VIEW)
@zabbix_bp.route('/zabbix/monitors')
@login_required
def zabbix_monitors_view():
    # AJUSTE FEITO: Agora verifica a permissão específica 'can_access_zabbix_mon'
    if not current_user.can('can_access_zabbix_mon'):
        flash('Acesso negado ao módulo de monitoramento.', 'danger')
        return redirect(url_for('index'))
    return render_template('zabbix_mon_feed.html', user=current_user)

@zabbix_bp.route('/api/zabbix/mon_alerts')
@login_required
def api_zabbix_mon_alerts():
    try:
        # ---> ADICIONE ESTA LINHA AQUI <---
        # Busca todas as URLs dos novos Zabbix configurados por equipe
        urls_motores = {tc.team_name: tc.zabbix_url.rstrip('/') for tc in TeamZabbixConfig.query.all() if tc.zabbix_url}
        
        # 1. Lê do Banco de Dados Local do Atlas (Para manter o estado do Kanban)
        hoje = datetime.now().date()
        inicio_do_dia = datetime.combine(hoje, datetime.min.time())
        
        # Pega alertas ativos OU que foram resolvidos hoje E que sejam MON/HADES
        db_alerts = ZabbixAlert.query.filter(
            or_(
                ZabbixAlert.status == 'active',
                and_(
                    ZabbixAlert.status.in_(['resolved_manual', 'resolved_auto']),
                    func.coalesce(ZabbixAlert.resolved_at, ZabbixAlert.last_seen) >= inicio_do_dia
                )
            ),
            or_(
                ZabbixAlert.name.ilike('%MON%'),
                ZabbixAlert.name.ilike('%HADES%')
            )
        ).order_by(desc(ZabbixAlert.start_time)).all()

        users_map = {u.id: u.display_name for u in User.query.all()}
        mon_alerts = []
        
        for a in db_alerts:
            # Pega o nome da trigger e já converte para maiúsculo
            trigger_name = (a.name or '').strip().upper()
            
            # === NOVA LÓGICA DE FILTRO SUPER FLEXÍVEL ===
            is_mon = (
                trigger_name.startswith('MON') or 
                '[MON]' in trigger_name or 
                '(MON)' in trigger_name or 
                ' MON ' in trigger_name or
                trigger_name == 'MON'
            )
            is_hades = 'HADES' in trigger_name
            
            # Se for algum dos dois, processa e envia para o front
            if is_mon or is_hades:
                tag_alerta = 'HADES' if is_hades else 'MON'
                
                # === CÁLCULO DE STATUS ESPELHADO AO ATLAS DESK ===
                status_local = 'Aberto'
                if a.status in ['resolved_manual', 'resolved_auto']:
                    status_local = 'Resolvido'
                elif a.ack_message and 'samuel' in a.ack_message.lower():
                    status_local = 'Samuel'
                elif a.ack_user_id:
                    status_local = 'Andamento'
                
                # Formata os dados para o Card
                owner_name = users_map.get(a.ack_user_id, '') if a.ack_user_id else ''
                
                # --- NOVO CÁLCULO DE TMA (Tempo Real de Resolução) ---
                # Pega a hora exata em que o analista clicou em assumir
                inicio_real = a.ack_at

                if inicio_real:
                    # Se assumiu, calcula do momento que pegou até o fechamento (ou até o momento atual se ainda estiver aberto)
                    fim = a.resolved_at if status_local == 'Resolvido' and a.resolved_at else datetime.now()
                    duration = fim - inicio_real
                    
                    days = duration.days
                    hours, remainder = divmod(duration.seconds, 3600)
                    minutes, _ = divmod(remainder, 60)
                    time_str = f"{minutes}m"
                    if hours > 0: time_str = f"{hours}h {minutes}m"
                    if days > 0: time_str = f"{days}d {hours}h {minutes}m"
                    
                    # Atualiza a hora de início visível na tela para a hora real em que pegou
                    start_time_display = inicio_real.strftime('%d/%m %H:%M')
                    
                else:
                    # Se ninguém pegou ainda, crava a mensagem de aguardando e mostra o tempo de disparo original do Zabbix
                    time_str = "Aguardando..."
                    start_time_display = a.start_time.strftime('%d/%m %H:%M')
                # --------------------------------------------------------

                # Se o alerta veio de um Multi-Zabbix e a chave de transição dele está ativa, usa a URL dele
                # Caso contrário, mantém o fallback seguro do Zabbix Global antigo
                base_url_zabbix = urls_motores.get(a.source_zabbix, zabbix_api.front_url)
                zabbix_link = f"{base_url_zabbix}/tr_events.php?triggerid={a.objectid}&eventid={a.eventid}"

                mon_alerts.append({
                    "eventid": a.eventid,
                    "host": a.host or 'Desconhecido',
                    "trigger": a.name,
                    "severity": a.severity,
                    "severity_cls": f"sev-{a.severity}",
                    "duration": time_str,
                    "start_time": start_time_display, # <--- AQUI A MUDANÇA
                    "opdata": a.description or '',
                    "ack": bool(a.ack_user_id),
                    "last_msg": a.ack_message or '',
                    "owner": owner_name,
                    "zabbix_link": zabbix_link,
                    "tag": tag_alerta,
                    "is_mon": is_mon,         # <--- FRONTEND VAI USAR ISSO
                    "is_hades": is_hades,     # <--- FRONTEND VAI USAR ISSO
                    "status_local": status_local
                })

        return jsonify({"success": True, "data": mon_alerts})

    except Exception as e:
        logger.error(f"Erro MON Alerts: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# --- NOVAS ROTAS PARA O TACTICAL DASHBOARD ---

@zabbix_bp.route('/api/zabbix/live_dashboard', methods=['GET'])
@login_required
def api_zabbix_live_dashboard():
    """
    Retorna os alertas ATIVOS do banco local, agrupados por Host Group.
    Focado em performance extrema para renderizar os blocos táticos.
    """
    try:
        # Busca apenas alertas críticos (5) e altos (4) que estão ativos
        active_alerts = ZabbixAlert.query.filter(
            ZabbixAlert.status == 'active',
            ZabbixAlert.severity.in_([4, 5])
        ).all()

        dashboard_data = {}
        urls_motores = {tc.team_name: tc.zabbix_url.rstrip('/') for tc in TeamZabbixConfig.query.all() if tc.zabbix_url}
        
        for alert in active_alerts:
            # Pega o grupo principal do alerta (ou 'Sem Grupo')
            grupo = alert.host_group or "Infraestrutura Geral"
            
            if grupo not in dashboard_data:
                dashboard_data[grupo] = {
                    "crit_count": 0,
                    "high_count": 0,
                    "alerts": []
                }
            
            # Incrementa os contadores
            if alert.severity == 5:
                dashboard_data[grupo]["crit_count"] += 1
            elif alert.severity == 4:
                dashboard_data[grupo]["high_count"] += 1
                
            base_url_zabbix = urls_motores.get(alert.source_zabbix, ZABBIX_FRONT_URL)
                
            # Guarda os dados do alerta para o Modal de detalhamento
            dashboard_data[grupo]["alerts"].append({
                "id": alert.eventid,
                "host": alert.host,
                "trigger": alert.name,
                "severity": alert.severity,
                "time": alert.start_time.strftime('%H:%M:%S'),
                "zabbix_link": f"{base_url_zabbix}/tr_events.php?triggerid={alert.objectid}&eventid={alert.eventid}"
            })

        return jsonify({"success": True, "data": dashboard_data})

    except Exception as e:
        logger.error(f"Erro Live Dashboard: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@zabbix_bp.route('/api/zabbix/exec_report', methods=['POST'])
@login_required
def api_zabbix_exec_report():
    try:
        filters = request.json or {}
        hoje = datetime.now()
        
        # 1. NOVO: Captura a Janela de Tempo (Filtro Operacional)
        time_window = filters.get('time_window', 'business') # 'business' ou '24h'
        
        # 2. Tratamento de Datas
        dt_start = datetime(hoje.year, hoje.month, 1)
        dt_end = hoje
        if filters.get('date_start') and filters.get('date_end'):
            dt_start = datetime.strptime(filters['date_start'], '%Y-%m-%d')
            dt_end = datetime.strptime(filters['date_end'], '%Y-%m-%d').replace(hour=23, minute=59, second=59)

        # 3. Tratamento de Grupos e Severidade
        filter_groups = filters.get('groups', [])
        if not filter_groups or filter_groups == ['PJ_DEFAULT']:
            filter_groups = DEFAULT_PJ_GROUPS

        sev_filter_raw = filters.get('severities', ['4', '5'])
        sev_filter = [int(s) for s in sev_filter_raw]

        # 4. Busca no Banco Local (Truth Source do Atlas)
        query = ZabbixAlert.query.filter(
            ZabbixAlert.start_time <= dt_end,
            or_(ZabbixAlert.resolved_at == None, ZabbixAlert.resolved_at >= dt_start),
            ZabbixAlert.host_group.in_(filter_groups),
            ZabbixAlert.severity.in_(sev_filter)
        )
        raw_alerts = query.all()

        # --- HELPER: CÁLCULO DE TEMPO DINÂMICO (PRODUÇÃO VS INTEGRAL) ---
        def calc_business_seconds(start, end):
            if not start or not end or start >= end: return 0
            
            # Se o filtro for 24h, o cálculo é a diferença bruta de tempo
            if time_window == '24h':
                return (end - start).total_seconds()
                
            # Se for 'business', restringe o cálculo à janela das 06:00 às 00:00
            total_sec = 0
            curr = start
            while curr < end:
                next_day = (curr + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
                biz_start = curr.replace(hour=6, minute=0, second=0, microsecond=0)
                biz_end = curr.replace(hour=23, minute=59, second=59, microsecond=999999)
                
                c_start = max(curr, biz_start)
                c_end = min(end, biz_end, next_day)
                
                if c_start < c_end:
                    total_sec += (c_end - c_start).total_seconds()
                curr = next_day
            return total_sec

        # Variáveis de Acúmulo para KPIs
        total_alerts = len(raw_alerts)
        total_ack = 0
        soma_mtta_segundos = 0
        qtd_mtta = 0
        soma_mttr_segundos = 0
        qtd_mttr = 0
        soma_downtime_segundos = 0
        
        downtime_alerts = []
        ignored_alerts = []
        host_counter = Counter()
        downtime_trigger_counter = Counter()
        
        # Inicializa Timeline
        timeline_data = {}
        for i in range((dt_end - dt_start).days + 1):
            d = (dt_start + timedelta(days=i)).strftime('%Y-%m-%d')
            timeline_data[d] = {'all': 0, 'down': 0}

        # 5. Processamento dos Dados
        for a in raw_alerts:
            host_counter[a.host] += 1
            dia_str = a.start_time.strftime('%Y-%m-%d')
            if dia_str in timeline_data:
                timeline_data[dia_str]['all'] += 1
            
            # A. Engajamento (Ack Rate)
            is_ack = bool(a.ack_user_id or a.ack_message or a.status in ['resolved_manual', 'resolved_auto'])
            if is_ack: 
                total_ack += 1
                
                # MTTA (Reconhecimento) - Respeitando a Janela Escolhida
                end_mtta = a.ack_at or a.resolved_at or datetime.now()
                delta_ack = calc_business_seconds(a.start_time, end_mtta)
                
                # Trava técnica de 12h para MTTA não distorcer médias
                if delta_ack > 43200: delta_ack = 43200
                if delta_ack > 0:
                    soma_mtta_segundos += delta_ack
                    qtd_mtta += 1

            # B. MTTR (Tempo de Resolução)
            if a.status in ['resolved_manual', 'resolved_auto'] and a.resolved_at:
                delta_res = calc_business_seconds(a.start_time, a.resolved_at)
                if delta_res > 0:
                    soma_mttr_segundos += delta_res
                    qtd_mttr += 1

            # C. Análise de Downtime (SLA)
            t_name_lower = (a.name or "").lower()
            h_name_lower = (a.host or "").lower()
            is_downtime = any(kw in t_name_lower for kw in DOWNTIME_KEYWORDS)
            is_ignored = any(kw in t_name_lower or kw in h_name_lower for kw in IGNORE_KEYWORDS)
            
            # Cálculo de tempo real afetado
            real_start = max(a.start_time, dt_start)
            real_end = a.resolved_at if (a.resolved_at and a.resolved_at < dt_end) else dt_end
            delta_down = calc_business_seconds(real_start, real_end)
            
            dur_h, dur_m = divmod(int(delta_down // 60), 60)
            dur_str = f"{dur_h}h {dur_m}m"

            if is_downtime and not is_ignored and delta_down > 0:
                if dia_str in timeline_data:
                    timeline_data[dia_str]['down'] += 1

                soma_downtime_segundos += delta_down
                downtime_trigger_counter[a.name] += 1
                
                downtime_alerts.append({
                    "start": a.start_time.strftime('%d/%m/%Y %H:%M'),
                    "host": a.host,
                    "trigger": a.name,
                    "severity": "Disaster" if a.severity == 5 else "High",
                    "status": "Resolvido" if a.resolved_at else "Pendente",
                    "duration": dur_str
                })
            else:
                motivo = "Fora da Janela Selecionada" if delta_down == 0 else "Filtro de Ruído (Proxy/Dev)"
                ignored_alerts.append({
                    "start": a.start_time.strftime('%d/%m/%Y %H:%M'),
                    "host": a.host,
                    "trigger": a.name,
                    "severity": "Disaster" if a.severity == 5 else "High",
                    "status": motivo,
                    "duration": dur_str if delta_down > 0 else "N/A"
                })

        # 6. Cálculo Final de Médias e SLA
        mtta_medio = (soma_mtta_segundos / qtd_mtta) if qtd_mtta > 0 else 0
        mtta_h, mtta_m = divmod(int(mtta_medio // 60), 60)
        mtta_str = f"{mtta_h}h {mtta_m}m" if mtta_h > 0 else f"{mtta_m}m {int(mtta_medio % 60)}s"
        
        mttr_medio = (soma_mttr_segundos / qtd_mttr) if qtd_mttr > 0 else 0
        mttr_h, mttr_m = divmod(int(mttr_medio // 60), 60)

        ack_percent = round((total_ack / total_alerts * 100), 1) if total_alerts > 0 else 0
        
        if len(downtime_alerts) > 0:
            media_down_segundos = soma_downtime_segundos / len(downtime_alerts)
        else:
            media_down_segundos = 0

        down_h, down_m = divmod(int(media_down_segundos // 60), 60)

        # Cálculo de Disponibilidade
        dias_no_periodo = max((dt_end - dt_start).days, 1)
        horas_disponiveis_dia = 24 if time_window == '24h' else 18
        horas_totais_periodo = dias_no_periodo * horas_disponiveis_dia
        
        horas_down_ajustado = media_down_segundos / 3600
        
        sla_percent = round(100 - ((horas_down_ajustado / horas_totais_periodo) * 100), 2)
        sla_percent = max(0, min(100, sla_percent)) # Clamp 0-100
        
        horas_up = max(0, horas_totais_periodo - horas_down_ajustado)
        up_h, up_m = divmod(int(horas_up * 60), 60)

        # Formatação de Séries dos Gráficos
        sorted_dates = sorted(timeline_data.keys())
        chart_dates_formatted = [datetime.strptime(d, '%Y-%m-%d').strftime('%d/%m') for d in sorted_dates]
        chart_down_vals = [timeline_data[d]['down'] for d in sorted_dates]
        chart_all_vals = [timeline_data[d]['all'] for d in sorted_dates]

        # Ordena a tabela do mais recente para o mais antigo
        downtime_alerts.reverse()
        ignored_alerts.reverse()

        return jsonify({
            "success": True,
            "kpis": {
                "volume": total_alerts,
                "ack_rate": ack_percent,
                "mtta": mtta_str,
                "mttr": f"{mttr_h}h {mttr_m}m",
                "downtime_str": f"{down_h}h {down_m}m",
                "uptime_str": f"{up_h}h {up_m}m",
                "sla_percent": sla_percent
            },
            "charts": {
                "top_hosts": dict(host_counter.most_common(10)),
                "top_triggers_down": dict(downtime_trigger_counter.most_common(10)),
                "timeline": {
                    "raw_dates": sorted_dates,
                    "labels": chart_dates_formatted,
                    "down": chart_down_vals,
                    "all": chart_all_vals
                }
            },
            "audit": downtime_alerts[:300],
            "ignored": ignored_alerts[:300]
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500

@zabbix_bp.route('/api/zabbix/tactical_alerts')
@login_required
def api_zabbix_tactical_alerts():
    """
    Endpoint EXCLUSIVO para o Tactical Dashboard (Performance Extrema).
    """
    try:
        cutoff = datetime.now() - timedelta(minutes=15)
        
        # 🚀 A MÁGICA DA VELOCIDADE: Faz o "JOIN" direto no banco de dados para evitar ler a tabela de usuários 1000 vezes!
        resultados = db.session.query(ZabbixAlert, User.display_name).outerjoin(
            User, ZabbixAlert.ack_user_id == User.id
        ).filter(
            or_(
                ZabbixAlert.status == 'active',
                and_(ZabbixAlert.status == 'resolved_manual', ZabbixAlert.last_seen >= cutoff)
            )
        ).order_by(desc(ZabbixAlert.start_time)).all()

        formatted = []
        
        # Como usamos .query(ZabbixAlert, User.display_name), o resultado é uma tupla
        for alert, nome_usuario in resultados:
            delta = datetime.now() - alert.start_time
            days = delta.days
            hours, remainder = divmod(delta.seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            
            dur_str = f"{minutes}m"
            if hours > 0: dur_str = f"{hours}h {minutes}m"
            if days > 0: dur_str = f"{days}d {hours}h {minutes}m"
            
            # Se a tupla trouxe o nome, usa ele. Se não, é porque o ack_user_id era nulo.
            owner_name = nome_usuario if alert.ack_user_id else ""
            if alert.ack_user_id and not nome_usuario:
                owner_name = "Atlas Bot" if alert.ack_message and 'Atlas Bot' in alert.ack_message else "Analista"
            
            # Formata os links da mesma forma que o Dashboard Principal
            my_urls = []
            if hasattr(alert, 'source_zabbix') and alert.source_zabbix and alert.source_zabbix != 'global':
                # Pega a URL do Zabbix V7 se estiver configurada
                from models import TeamZabbixConfig
                config = TeamZabbixConfig.query.filter_by(team_name=alert.source_zabbix).first()
                if config and config.zabbix_url:
                    base_url = config.zabbix_url.rstrip('/')
                    my_urls.append(f"{base_url}/tr_events.php?triggerid={alert.objectid}&eventid={alert.eventid}")
            
            # Se não achou link do V7, usa o V4 padrão
            if not my_urls:
                my_urls.append(f"{ZABBIX_FRONT_URL}/tr_events.php?triggerid={alert.objectid}&eventid={alert.eventid}")

            formatted.append({
                "id": alert.eventid,
                "objectid": alert.objectid,
                "host": alert.host,
                "group": alert.host_group,
                "groups": [alert.host_group],
                "severity": alert.severity,
                "trigger": alert.name,
                "opdata": alert.description,
                "duration": dur_str,
                "start_date": alert.start_time.strftime('%d/%m %H:%M'),
                "owner_name": owner_name,
                "owner_id": alert.ack_user_id,
                "zabbix_ack": True if alert.ack_message else False,
                "is_chronic": days >= 1,
                "zabbix_links": my_urls
            })
            
        return jsonify({"success": True, "data": formatted})
    except Exception as e:
        logger.error(f"Erro Tactical Alerts: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@zabbix_bp.route('/zabbix/mon_analytics', methods=['GET', 'POST'])
@login_required
def zabbix_mon_analytics_view():
    if not current_user.can('can_access_zabbix_mon'):
        flash('Acesso negado ao módulo de monitoramento.', 'danger')
        return redirect(url_for('index'))

    hoje = datetime.now()
    data_fim_default = hoje.strftime('%Y-%m-%d')
    data_inicio_default = (hoje - timedelta(days=7)).strftime('%Y-%m-%d')

    origem_selecionada = 'all'
    report_data = None

    if request.method == 'POST':
        try:
            dt_inicio = datetime.strptime(request.form.get('data_inicio'), '%Y-%m-%d').replace(hour=0, minute=0, second=0)
            dt_fim = datetime.strptime(request.form.get('data_fim'), '%Y-%m-%d').replace(hour=23, minute=59, second=59)
            origem_selecionada = request.form.get('origem', 'all')

            # 1. Busca TODOS os Alertas do Zabbix no período selecionado
            raw_alerts = ZabbixAlert.query.filter(ZabbixAlert.start_time.between(dt_inicio, dt_fim)).order_by(desc(ZabbixAlert.start_time)).all()

            # 2. Filtra de forma cirúrgica pelas regras MON / HADES
            filtered_alerts = []
            for a in raw_alerts:
                t_name = (a.name or '').strip().upper()
                is_mon = t_name.startswith('MON') or '[MON]' in t_name or '(MON)' in t_name or ' MON ' in t_name or t_name == 'MON'
                is_hades = 'HADES' in t_name

                if origem_selecionada == 'mon' and not is_mon: continue
                if origem_selecionada == 'hades' and not is_hades: continue
                if origem_selecionada == 'all' and not (is_mon or is_hades): continue

                filtered_alerts.append(a)

            if not filtered_alerts:
                flash("Nenhum dado encontrado para os filtros selecionados.", "info")
            else:
                # 3. Motores de Cálculos Matemáticos e Contadores
                total = len(filtered_alerts)
                resolvidos = 0
                ack_count = 0
                soma_mttr = 0
                qtd_mttr = 0

                status_counts = {'Aberto': 0, 'Em Andamento': 0, 'Resolvido': 0}
                trigger_counts = Counter()
                host_counts = Counter()
                analyst_scores = Counter()
                timeline_counts = {}

                # Mapa de Usuários e Times
                users_map = {}
                for u in User.query.all():
                    team_primary = u.teams.split(',')[0].strip() if u.teams else 'OPERACIONAL'
                    users_map[str(u.id)] = {'name': u.display_name, 'team': team_primary}

                # Prepara Linha do Tempo com Datas ISO
                iso_dates = []
                for i in range((dt_fim - dt_inicio).days + 1):
                    d_obj = dt_inicio + timedelta(days=i)
                    dia_str = d_obj.strftime('%d/%m')
                    iso_str = d_obj.strftime('%Y-%m-%d')
                    timeline_counts[dia_str] = 0
                    if iso_str not in iso_dates: iso_dates.append(iso_str)

                # --- LISTA DETALHADA PARA A TABELA DE LOGS ---
                todos_alertas_front = []
                urls_motores = {tc.team_name: tc.zabbix_url.rstrip('/') for tc in TeamZabbixConfig.query.all() if tc.zabbix_url}

                for a in filtered_alerts:
                    status_local = 'Aberto'
                    if a.status in ['resolved_manual', 'resolved_auto']:
                        status_local = 'Resolvido'
                        resolvidos += 1
                        ack_count += 1
                    elif a.ack_user_id:
                        status_local = 'Em Andamento'
                        ack_count += 1

                    status_counts[status_local] += 1

                    # Linha do Tempo
                    dia_str = a.start_time.strftime('%d/%m')
                    if dia_str in timeline_counts:
                        timeline_counts[dia_str] += 1

                    # Contadores
                    trigger_counts[a.name] += 1
                    host_name = a.host or 'Desconhecido'
                    host_counts[host_name] += 1

                    # LEADERBOARD E TMA
                    nome_responsavel = '-'
                    if a.ack_user_id:
                        u_data = users_map.get(str(a.ack_user_id), {'name': 'Sistema', 'team': 'N/A'})
                        analyst_scores[(str(a.ack_user_id), u_data['name'], u_data['team'])] += 1
                        nome_responsavel = u_data['name']

                        if status_local == 'Resolvido' and a.resolved_at:
                            delta = (a.resolved_at - a.start_time).total_seconds()
                            if delta > 0:
                                soma_mttr += delta
                                qtd_mttr += 1

                    base_url_zabbix = urls_motores.get(a.source_zabbix, zabbix_api.front_url)

                    # Alimentando a tabela de logs
                    todos_alertas_front.append({
                        "id": a.eventid,
                        "objectid": a.objectid,
                        "host": host_name,
                        "trigger": a.name,
                        "severity": a.severity,
                        "status": status_local,
                        "responsavel": nome_responsavel,
                        "data_str": a.start_time.strftime('%d/%m %H:%M'),
                        "iso_date": a.start_time.strftime('%Y-%m-%d'),
                        "zabbix_url": f"{base_url_zabbix}/tr_events.php?triggerid={a.objectid}&eventid={a.eventid}"
                    })

                # 4. Formatação Final
                ack_rate = round((ack_count / total * 100), 1) if total > 0 else 0
                avg_mttr = (soma_mttr / qtd_mttr) if qtd_mttr > 0 else 0
                h_mttr, m_mttr = divmod(int(avg_mttr // 60), 60)
                tma_str = f"{h_mttr}h {m_mttr}m" if h_mttr > 0 else f"{m_mttr}m"

                top_analysts = [{"name": name, "team": team, "score": score} for (uid, name, team), score in analyst_scores.most_common(10)]
                
                top_triggers_labels = [k[:45] + "..." if len(k) > 45 else k for k, v in trigger_counts.most_common(10)]
                top_triggers_data = [v for k, v in trigger_counts.most_common(10)]
                
                top_hosts_labels = [k[:30] + "..." if len(k) > 30 else k for k, v in host_counts.most_common(10)]
                top_hosts_data = [v for k, v in host_counts.most_common(10)]

                # Insights Corporativos
                insights_ia = []
                if total > 0:
                    insights_ia.append({
                        "tipo": "Volume Operacional", "icone": "bx-pulse", "cor": "var(--atlas-cyan)",
                        "texto": f"A central <b>{origem_selecionada.upper()}</b> processou <b>{total} chamados</b> no período selecionado. A taxa de atuação técnica foi de <b>{ack_rate}%</b>."
                    })
                if timeline_counts:
                    dia_pico = max(timeline_counts, key=timeline_counts.get)
                    valor_pico = timeline_counts[dia_pico]
                    insights_ia.append({
                        "tipo": "Pico de Demanda", "icone": "bx-bar-chart", "cor": "var(--atlas-rose)",
                        "texto": f"O dia de maior volumetria foi <b>{dia_pico}</b>, contabilizando <b>{valor_pico} alertas</b> processados."
                    })
                if avg_mttr > 0:
                    cor_mttr = "var(--atlas-emerald)" if avg_mttr < 3600 else "var(--atlas-amber)"
                    texto_bom = "Tempo de resolução dentro das margens operacionais." if avg_mttr < 3600 else "Fila com sinais de represamento no tempo de tratativa."
                    insights_ia.append({
                        "tipo": "Tempo de Tratativa (MTTR)", "icone": "bx-stopwatch", "cor": cor_mttr,
                        "texto": f"O Tempo Médio de Resolução da equipe está em <b>{tma_str}</b>. {texto_bom}"
                    })

                report_data = {
                    "kpis": {"volume": total, "resolved": resolvidos, "ack_rate": ack_rate, "tma": tma_str},
                    "timeline": {"labels": list(timeline_counts.keys()), "iso_dates": iso_dates, "data": list(timeline_counts.values())},
                    "status": {"labels": list(status_counts.keys()), "data": list(status_counts.values())},
                    "top_analysts": top_analysts,
                    "top_triggers": {"labels": top_triggers_labels, "data": top_triggers_data},
                    "top_hosts": {"labels": top_hosts_labels, "data": top_hosts_data},
                    "insights_ia": insights_ia,
                    "todos_alertas": todos_alertas_front
                }

        except Exception as e:
            traceback.print_exc()
            flash(f"Erro ao processar relatório: {e}", 'danger')

    return render_template('zabbix_mon_analytics.html',
                           user=current_user,
                           data_inicio=request.form.get('data_inicio', data_inicio_default),
                           data_fim=request.form.get('data_fim', data_fim_default),
                           origem_selecionada=origem_selecionada,
                           report_data=report_data)

@zabbix_bp.route('/api/zabbix/investigate/<eventid>')
@login_required
def api_zabbix_investigate(eventid):
    try:
        # Descobre a origem e usa a conexão certa
        alert = ZabbixAlert.query.filter_by(eventid=eventid).first()
        source = alert.source_zabbix if alert else 'global'
        zapi = get_zabbix_connection(source) 
        
        # 2. ESCANEAMENTO PROFUNDO
        event_data = zapi._post("event.get", {
            "eventids": eventid,
            "selectTags": "extend",
            "selectHosts": ["name"],
            "selectRelatedObject": ["triggerid"]
        })
        
        if not event_data or not event_data.get('result'):
            return jsonify({"error": "Evento não encontrado no Zabbix."}), 404
            
        evt = event_data['result'][0]
        host_name = evt['hosts'][0]['name'] if evt.get('hosts') else "Desconhecido"
        trigger_id = evt.get('relatedObject', {}).get('triggerid')
        tags = [f"{t['tag']}: {t['value']}" for t in evt.get('tags', [])]
        
        # 3. Busca as métricas reais (Itens)
        metricas_texto = ""
        if trigger_id:
            items_data = zapi._post("item.get", {"triggerids": trigger_id, "output": ["name", "lastvalue", "units"]})
            for it in items_data.get('result', []):
                metricas_texto += f"- {it['name']}: {it['lastvalue']} {it['units']}\n"

        # 4. PROMPT ULTRA ESTRUTURADO PARA O ATLAS INVESTIGADOR
        prompt = f"""Você é o Atlas Investigador Sênior. Gere um relatório técnico em HTML.
        Use as classes CSS: 'inv-card', 'inv-title', 'inv-label', 'inv-value', 'inv-status'.
        
        DADOS:
        - Host: {host_name}
        - Gatilho: {evt['name']}
        - Tags: {", ".join(tags)}
        - Métricas: {metricas_texto}

        ESTRUTURA DO HTML:
        1. Um header com o status do host.
        2. Uma tabela ou grid com as métricas atuais.
        3. Um plano de ação 'Passo a Passo' com ícones.
        4. NÃO use markdown (### ou **). Use apenas tags HTML puras.
        """
        
        resposta_ia = gerar_resposta_llm(prompt, model="qwen2.5:3b")
        
        # Limpeza e Formatação Visual Premium
        html_limpo = resposta_ia.replace('```html', '').replace('```', '').strip()
        
        return jsonify({
            "html": html_limpo,
            "host": host_name,
            "trigger": evt['name']
        })

    except Exception as e:
        print(f"Erro Investigador: {e}")
        return jsonify({"error": str(e)}), 500
    
@zabbix_bp.route('/api/zabbix/filter_presets', methods=['GET', 'POST'])
@login_required
def api_filter_presets():
    if request.method == 'GET':
        presets = ZabbixFilterPreset.query.order_by(ZabbixFilterPreset.nome).all()
        return jsonify([{
            'id': p.id, 
            'nome': p.nome, 
            'grupos': p.grupos, 
            'severidades': p.severidades,
            'equipe_dona': p.equipe_dona or 'Global',
            'zabbix_source': getattr(p, 'zabbix_source', 'global') # Puxa a origem nova
        } for p in presets])

    if request.method == 'POST':
        if current_user.role.name != 'master_admin':
            return jsonify({'success': False, 'error': 'Acesso negado ao painel de infraestrutura.'}), 403
        
        data = request.json
        preset_id = data.get('id')
        nome_preset = data.get('nome', '').strip()
        equipe_alvo = data.get('equipe_dona')
        zabbix_origem = data.get('zabbix_source', 'global') # <--- CAPTURA A ORIGEM AQUI
        
        if not nome_preset:
            return jsonify({'success': False, 'error': 'Nome da view/preset obrigatório.'}), 400
            
        grupos_str = ','.join(data.get('grupos', [])) if isinstance(data.get('grupos'), list) else data.get('grupos')
        sevs_str = ','.join(data.get('severidades', [])) if isinstance(data.get('severidades'), list) else data.get('severidades')

        try:
            if preset_id:
                preset = db.session.get(ZabbixFilterPreset, int(preset_id))
                if not preset:
                    return jsonify({'success': False, 'error': 'Filtro não encontrado.'}), 404
                preset.nome = nome_preset
                preset.grupos = grupos_str
                if 'severidades' in data:
                    preset.severidades = sevs_str
                preset.equipe_dona = equipe_alvo if equipe_alvo and equipe_alvo != 'Global' else None
                preset.zabbix_source = zabbix_origem # <--- ATUALIZA ORIGEM
            else:
                novo = ZabbixFilterPreset(
                    nome=nome_preset,
                    grupos=grupos_str,
                    severidades=sevs_str,
                    equipe_dona=equipe_alvo if equipe_alvo and equipe_alvo != 'Global' else None,
                    zabbix_source=zabbix_origem # <--- SALVA ORIGEM
                )
                db.session.add(novo)
                
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500

@zabbix_bp.route('/api/zabbix/filter_presets/<int:pid>', methods=['DELETE'])
@login_required
def delete_filter_preset(pid):
    # Trava Absoluta: EXCLUSIVO para Master Admin!
    if current_user.role.name != 'master_admin':
        return jsonify({'success': False}), 403
        
    p = ZabbixFilterPreset.query.get(pid)
    if p:
        db.session.delete(p)
        db.session.commit()
    return jsonify({'success': True})

# ==============================================================================
# AUTO-ASSIGN JUSTO (fila por equipe + menor carga + janela de 1h + 8s de espera)
# Heartbeat em /api/zabbix/auto_assign/heartbeat; decisão da vez no claim.
# ==============================================================================
AA_POOL_TTL = 25                       # s sem heartbeat = fora da fila
AA_FREE_AFTER = 8                      # s: se o dono da vez não pegou, libera pra fila toda
AA_LOAD_WINDOW = timedelta(hours=1)    # alerta com o técnico há mais de 1h não pesa na carga


def _aa_teams(user):
    # 🌟 NOVA REGRA: Retorna UMA LISTA com TODAS as equipes do analista!
    return [t.strip() for t in user.teams.split(',')] if user.teams else ['Geral']

def _aa_pool_key(team):
    return f"aa_pool:{team}"

def _aa_last_key(team):
    return f"aa_last:{team}"

def _aa_wait_key(alerta):
    return f"aa_wait:{alerta.source_zabbix or 'global'}:{alerta.eventid}"

def _aa_presets(teams_list):
    # 🌟 NOVA REGRA: Busca presets de TODAS as equipes passadas na lista
    return ZabbixFilterPreset.query.filter(ZabbixFilterPreset.equipe_dona.in_(teams_list)).all()

def _aa_team_sources(teams_list):
    return {(p.zabbix_source or 'global') for p in _aa_presets(teams_list)}

def _aa_presets_map(teams_list):
    """Presets agrupados por equipe (pra saber a qual equipe cada alerta pertence)."""
    presets_all = _aa_presets(teams_list)
    mapa = defaultdict(list)
    for p in presets_all:
        mapa[p.equipe_dona].append(p)
    return mapa

def _aa_alert_da_equipe(alerta, presets):
    """O alerta pertence à equipe se algum preset dela cobre a origem e o grupo do host."""
    src = alerta.source_zabbix or 'global'
    for p in presets:
        if (p.zabbix_source or 'global') != src:
            continue
        grupos = [g.strip() for g in (p.grupos or '').split(',') if g.strip()]
        if not grupos or alerta.host_group in grupos:
            return True
    return False


def _escape_like(s):
    return (s or '').replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


def _aa_nome_base(nome):
    palavras = (nome or '').split()
    return " ".join(palavras[:-1]) if len(palavras) >= 4 else (nome or '')


def _aa_cluster_key(a):
    # mesma ideia do agrupamento do claim: origem + host + severidade + nome-base
    return (a.source_zabbix or 'global', a.host, a.severity, _aa_nome_base(a.name).lower())


def _aa_cargas(user_ids):
    """Cards em 'Meus alertas' de cada técnico (contados por cluster).
    Ignora alertas com o técnico há mais de 1h e os marcados como [ATUADO]."""
    limite = datetime.now() - AA_LOAD_WINDOW
    ref = func.coalesce(ZabbixAlert.ack_at, ZabbixAlert.atlas_created_at)
    linhas = db.session.query(
        ZabbixAlert.ack_user_id, ZabbixAlert.source_zabbix, ZabbixAlert.host,
        ZabbixAlert.severity, ZabbixAlert.name
    ).filter(
        ZabbixAlert.status == 'active',
        ZabbixAlert.ack_user_id.in_([str(u) for u in user_ids]),
        ref >= limite,
        or_(ZabbixAlert.ack_message.is_(None), ~ZabbixAlert.ack_message.ilike('%[ATUADO]%'))
    ).all()

    clusters = defaultdict(set)
    for r in linhas:
        clusters[str(r.ack_user_id)].add(_aa_cluster_key(r))
    return {str(u): len(clusters.get(str(u), ())) for u in user_ids}


def _aa_minha_vez(team, user_id):
    """True se é a vez de quem chamou: menor carga; empate = quem recebeu há mais tempo."""
    agora = time.time()
    pool = redis_db.zrangebyscore(_aa_pool_key(team), agora - AA_POOL_TTL, '+inf')
    if user_id not in pool:
        pool.append(user_id)
    if len(pool) == 1:
        return True  # sozinho na fila: não gasta consulta nenhuma no banco

    cargas = _aa_cargas(pool)
    ultimos = redis_db.hmget(_aa_last_key(team), pool)
    ranking = sorted(
        zip(pool, ultimos),
        key=lambda x: (cargas.get(x[0], 0), float(x[1] or 0), x[0])
    )
    return ranking[0][0] == user_id


# ------------------------------------------------------------------------------
# HEARTBEAT: entra/sai da fila. Independe de haver alerta na tela.
# ------------------------------------------------------------------------------
@zabbix_bp.route('/api/zabbix/auto_assign/heartbeat', methods=['POST'])
@login_required
def api_zabbix_auto_assign_heartbeat():
    data = request.get_json(silent=True) or {}
    teams = _aa_teams(current_user)
    uid = str(current_user.id).strip()

    # Desligou o botão / AFK / fechou a aba: sai da fila de TODAS as equipes na hora
    if data.get('active') is False:
        pipe = redis_db.pipeline()
        for t in teams:
            pipe.zrem(_aa_pool_key(t), uid)
        pipe.execute()
        return jsonify({"success": True, "in_pool": False})

    # Só entra na fila quem tem token pessoal de TODOS os Zabbix das equipes
    tokens_map = dict(session.get('zbx_user_tokens', {}) or {})
    if session.get('zbx_user_token') and 'global' not in tokens_map:
        tokens_map['global'] = session.get('zbx_user_token')
        
    faltando = [s for s in _aa_team_sources(teams) if not tokens_map.get(s)]
    if faltando:
        pipe = redis_db.pipeline()
        for t in teams:
            pipe.zrem(_aa_pool_key(t), uid)
        pipe.execute()
        return jsonify({"success": True, "in_pool": False, "reason": "AUTH_REQUIRED", "missing_sources": faltando})

    agora = time.time()
    pipe = redis_db.pipeline()
    for t in teams:
        key = _aa_pool_key(t)
        pipe.zadd(key, {uid: agora})
        pipe.zremrangebyscore(key, '-inf', agora - AA_POOL_TTL)
        pipe.expire(key, 3600)
    pipe.execute()
    return jsonify({"success": True, "in_pool": True})


# ------------------------------------------------------------------------------
# CLAIM
# ------------------------------------------------------------------------------
@zabbix_bp.route('/api/zabbix/auto_assign/claim', methods=['POST'])
@login_required
def api_zabbix_auto_assign_claim():
    from sqlalchemy import tuple_
    data = request.get_json(silent=True) or {}
    pares_auto = _parse_pares(data.get('event_ids', []))
    if not pares_auto:
        return jsonify({"success": True, "claimed": 0})

    user_id = str(current_user.id).strip()
    teams = _aa_teams(current_user)
    presets_map = _aa_presets_map(teams)
    
    if not any(presets_map.values()):
        # Nenhuma das equipes tem preset: não assume nada
        return jsonify({"success": True, "claimed": 0, "reason": "no_preset"})

    config_global = AtlasConfig.query.first()
    team_configs_map = {tc.team_name: tc for tc in TeamZabbixConfig.query.all()}

    def automacao_liberada(alerta):
        if alerta.source_zabbix and alerta.source_zabbix != 'global':
            tc = team_configs_map.get(alerta.source_zabbix)
            return bool(tc and tc.auto_ack_enabled)
        return bool(config_global and config_global.auto_ack_enabled)

    # 🌟 Descobre a qual equipe cada alerta pertence, ANTES de travar qualquer coisa
    def equipe_do_alerta(alerta):
        for t in teams:  # respeita a ordem: principal tem prioridade em caso de ambiguidade
            if _aa_alert_da_equipe(alerta, presets_map.get(t, [])):
                return t
        return None

    livre = or_(
        ZabbixAlert.ack_user_id.is_(None),
        func.trim(ZabbixAlert.ack_user_id) == '',
        ZabbixAlert.ack_user_id == 'None'
    )

    # Ordem determinística: mais grave primeiro, depois o mais antigo
    candidatos = ZabbixAlert.query.filter(
        tuple_(ZabbixAlert.eventid, ZabbixAlert.source_zabbix).in_(pares_auto),
        livre,
        ZabbixAlert.status == 'active'
    ).order_by(ZabbixAlert.severity.desc(), ZabbixAlert.start_time.asc()
    ).with_for_update(skip_locked=True).limit(30).all()

    # equipe de cada candidato + filtro de automação liberada
    candidatos_com_equipe = [(a, equipe_do_alerta(a)) for a in candidatos]
    candidatos_com_equipe = [(a, t) for a, t in candidatos_com_equipe if t and automacao_liberada(a)]
    
    if not candidatos_com_equipe:
        db.session.rollback()
        return jsonify({"success": True, "claimed": 0})

    # 🔒 Só AGORA trava — usando a equipe do PRIMEIRO candidato elegível (o mais grave/antigo)
    team = candidatos_com_equipe[0][1]
    obteve = db.session.execute(
        text("SELECT pg_try_advisory_xact_lock(hashtext(:k))"), {"k": f"aa_claim_{team}"}
    ).scalar()
    
    if not obteve:
        db.session.rollback()
        return jsonify({"success": True, "claimed": 0, "reason": "busy"})

    # só segue com os candidatos que são dessa mesma equipe travada
    livres = [a for a, t in candidatos_com_equipe if t == team]

    # ⚖️ De quem é a vez?
    agora = time.time()
    if _aa_minha_vez(team, user_id):
        elegiveis = livres
    else:
        chaves = [_aa_wait_key(a) for a in livres]
        marcas = redis_db.mget(chaves)
        # só pode furar a vez o alerta que já está esperando há mais de AA_FREE_AFTER
        elegiveis = [a for a, m in zip(livres, marcas) if m and agora - float(m) > AA_FREE_AFTER]
        if not elegiveis:
            pipe = redis_db.pipeline()
            for k in chaves:
                pipe.set(k, agora, nx=True, ex=120)  # começa a contar a espera
            pipe.execute()
            db.session.rollback()
            return jsonify({"success": True, "claimed": 0, "reason": "yield_to_colleague"})

    # 1 cluster por chamada (mesmo host, severidade e nome-base)
    base_alert = elegiveis[0]
    nome_base = _aa_nome_base(base_alert.name)
    padrao = _escape_like(nome_base) + "%" if len((base_alert.name or '').split()) >= 4 else _escape_like(base_alert.name)

    familia = ZabbixAlert.query.filter(
        tuple_(ZabbixAlert.eventid, ZabbixAlert.source_zabbix).in_(pares_auto),
        ZabbixAlert.source_zabbix == base_alert.source_zabbix,
        ZabbixAlert.host == base_alert.host,
        ZabbixAlert.severity == base_alert.severity,
        ZabbixAlert.name.ilike(padrao, escape='\\'),
        livre,
        ZabbixAlert.status == 'active'
    ).all()

    claimed_ids = []
    claimed_keys = []
    mapa_origem = defaultdict(list)
    agora_dt = datetime.now()
    
    for a in familia:
        # 🛡️ A MÁGICA FINAL: Garante que os membros da família/cluster também pertencem à equipe travada!
        a_team = equipe_do_alerta(a)
        if a_team != team or not automacao_liberada(a):
            continue
            
        a.last_seen = agora_dt
        a.ack_user_id = user_id
        a.ack_message = "Em Atendimento (Auto-Assign)"
        a.ack_at = agora_dt
        a.hidden_on_dash = False
        claimed_ids.append(a.eventid)
        claimed_keys.append(_aa_wait_key(a))
        mapa_origem[a.source_zabbix or 'global'].append(a.eventid)

    if not claimed_ids:
        db.session.rollback()
        return jsonify({"success": True, "claimed": 0})

    # 🛡️ Trava anti-Atlas: sem token pessoal de alguma origem, não assume
    tokens_map = dict(session.get('zbx_user_tokens', {}) or {})
    if session.get('zbx_user_token') and 'global' not in tokens_map:
        tokens_map['global'] = session.get('zbx_user_token')
    faltando = [s for s in mapa_origem.keys() if not tokens_map.get(s)]
    if faltando:
        db.session.rollback()
        return jsonify({"success": False, "error": "AUTH_REQUIRED", "missing_sources": faltando}), 401

    try:
        db.session.commit()  # o commit também solta o advisory lock
    except Exception as db_err:
        db.session.rollback()
        logger.error(f"Erro ao comitar Auto-Assign no banco: {db_err}")
        return jsonify({"success": False, "error": "Falha na transação do banco de dados."}), 500

    # Registra o "último a receber" (desempate) e limpa a marca de espera
    try:
        redis_db.hset(_aa_last_key(team), user_id, time.time())
        redis_db.delete(*claimed_keys)
    except Exception as redis_err:
        logger.warning(f"Auto-Assign: falha ao atualizar Redis pós-commit: {redis_err}")

    from tasks import bg_zabbix_call_task
    try:
        bg_zabbix_call_task.delay(dict(mapa_origem), "Em Atendimento (Auto-Assign)", 6, tokens_map)
    except Exception as celery_err:
        logger.error(f"⚠️ Celery indisponível no Auto-Assign: {celery_err}")

    return jsonify({
        "success": True,
        "claimed": len(claimed_ids),
        "eventid": claimed_ids[0],
        "claimed_ids": claimed_ids
    })


# ------------------------------------------------------------------------------
# (OPCIONAL) índice pra consulta de carga — só se a tabela zabbix_alert for grande.
# Coloque em garantir_atualizacao_banco() no bot.py, no mesmo padrão dos outros:
#
#   CREATE INDEX IF NOT EXISTS ix_zabbix_alert_ack_user_active
#       ON zabbix_alert (ack_user_id) WHERE status = 'active';
# ------------------------------------------------------------------------------


@zabbix_bp.route('/api/zabbix/multi/test_connection', methods=['POST'])
@login_required
def api_zabbix_multi_test():
    """ Rota para testar a conexão com um Zabbix dinâmico e trazer os grupos """
    if not current_user.can('can_manage_zabbix_config'):
        return jsonify({"success": False, "error": "Sem permissão"}), 403
        
    data = request.json
    zbx_url = data.get('url', '').rstrip('/') + "/api_jsonrpc.php"
    zbx_user = data.get('user', '').strip()
    zbx_pass = data.get('password', '').strip()
    team_name = data.get('team', '').strip() # <--- PEGA O TIME ENVIADO
    
    # 🌟 A MÁGICA: Se a senha for as bolinhas da edição, pega a verdadeira no banco!
    if zbx_pass == "••••••••••••" and team_name:
        from models import TeamZabbixConfig
        tc = TeamZabbixConfig.query.filter_by(team_name=team_name).first()
        if tc and tc.api_password:
            zbx_pass = _get_decrypted_zabbix_pass(tc.api_password)
    
    if not zbx_url or not zbx_user or not zbx_pass:
        return jsonify({"success": False, "error": "Credenciais incompletas."}), 400

    try:
        token = None
        
        # 🌟 MÁGICA: Se a senha tiver 64 caracteres ou o usuário for 'token', assume API Token
        if len(zbx_pass) >= 32 and (zbx_user.lower() in ['token', 'api', 'atlas'] or len(zbx_pass) == 64):
            token = zbx_pass
        else:
            # Tenta o Login Zabbix V7/V6.4 (Usa 'username')
            login_payload = {
                "jsonrpc": "2.0", "method": "user.login", 
                "params": {"username": zbx_user, "password": zbx_pass}, "id": 1
            }
            r_login = requests.post(zbx_url, json=login_payload, timeout=5, verify=False)
            res_login = r_login.json()
            
            # Se falhar, tenta Zabbix Legado V4 (Usa 'user')
            if 'result' not in res_login:
                login_payload["params"] = {"user": zbx_user, "password": zbx_pass}
                r_login = requests.post(zbx_url, json=login_payload, timeout=5, verify=False)
                res_login = r_login.json()
            
            if 'result' not in res_login:
                return jsonify({"success": False, "error": "Falha na autenticação. Verifique usuário/senha."}), 401
                
            token = res_login['result']
        
        # Busca os Grupos para provar que funciona
        groups_payload = {
            "jsonrpc": "2.0", "method": "hostgroup.get", 
            "params": {"output": ["name"], "real_hosts": True}, 
            "auth": token, "id": 2
        }
        r_groups = requests.post(zbx_url, json=groups_payload, timeout=5, verify=False)
        res_groups = r_groups.json()
        
        if 'result' not in res_groups:
            return jsonify({"success": False, "error": "Token inválido ou sem permissão de leitura de grupos."}), 403
            
        grupos = sorted([g['name'] for g in res_groups.get('result', [])])
        
        return jsonify({"success": True, "groups": grupos})
        
    except Exception as e:
        return jsonify({"success": False, "error": f"Erro de conexão: {str(e)}"}), 500


@zabbix_bp.route('/admin/automations/multi_zabbix/save', methods=['POST'])
@login_required
def admin_automations_multi_zabbix_save():
    """ Rota para salvar a configuração da equipe no banco """
    if not current_user.can('can_manage_zabbix_config'):
        flash("Acesso negado.", "danger")
        return redirect(url_for('index'))
        
    try:
        team_name = request.form.get('mz_team')
        url = request.form.get('mz_url')
        user = request.form.get('mz_user')
        password = request.form.get('mz_password')
        
        # O formulário envia 'on' se o checkbox estiver marcado
        auto_ack = request.form.get('mz_auto_ack') == 'on'
        shadow_mode = request.form.get('disable_global') == 'on'
        buffer_min = int(request.form.get('mz_buffer', 5))
        
        sevs = request.form.getlist('mz_severities')
        groups = request.form.get('mz_groups', '')

        # Atualiza ou cria a configuração
        config = TeamZabbixConfig.query.filter_by(team_name=team_name).first()
        if not config:
            config = TeamZabbixConfig(team_name=team_name)
            db.session.add(config)
            
        from azure_auth import encrypt_token

        config.zabbix_url = url
        config.api_user = user
        if password and password != "••••••••••••":  # Só atualiza a senha se ele digitou uma nova
            config.api_password = encrypt_token(password)
            
        config.auto_ack_enabled = auto_ack
        config.shadow_mode_active = shadow_mode
        config.buffer_minutes = buffer_min
        config.target_severities = ",".join(sevs)
        config.whitelist_groups = groups
        
        db.session.commit()
        flash(f"Instância Zabbix da equipe {team_name} salva com sucesso!", "success")
        
    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao salvar: {e}", "danger")
        
    return redirect(url_for('admin_automations'))
@zabbix_bp.route('/admin/automations/multi_zabbix/delete', methods=['POST'])
@login_required
def admin_automations_multi_zabbix_delete():
    """ Rota para excluir uma instância Zabbix de uma equipe """
    if not current_user.can('can_manage_zabbix_config'):
        flash("Acesso negado.", "danger")
        return redirect(url_for('index'))
        
    try:
        config_id = request.form.get('id')
        config = db.session.get(TeamZabbixConfig, config_id)
        
        if config:
            nome_time = config.team_name
            db.session.delete(config)
            db.session.commit()
            flash(f"Instância Zabbix da equipe {nome_time} removida com sucesso!", "success")
        else:
            flash("Configuração não encontrada.", "warning")
            
    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao excluir: {e}", "danger")
        
    return redirect(url_for('admin_automations'))

@zabbix_bp.route('/api/zabbix/fast_ping', methods=['POST'])
@login_required
def api_zabbix_fast_ping():
    try: # <--- 🛡️ INÍCIO DA BLINDAGEM MÁXIMA
        data = request.json
        event_id = data.get('event_id')
        cliente_id = data.get('cliente_id') # Enviado quando a IA está aprendendo

        # 1. Busca o Alerta
        alert = ZabbixAlert.query.filter_by(eventid=event_id).first()
        if not alert:
            return jsonify({'success': False, 'error': 'Alerta não encontrado.'})

        cliente = None

        # 2. SE O USUÁRIO MANDOU O CLIENTE, VAMOS ENSINAR O ATLAS
        if cliente_id:
            cliente = db.session.get(ClienteChamado, cliente_id)
            if cliente:
                ZabbixAlert.query.filter_by(host=alert.host).update({'cliente_id_manual': cliente.id})
                
                # Aprendizado 2: Puxamos a rota salva do cliente
                if not cliente.teams_channel_id:
                    return jsonify({'success': False, 'error': 'needs_channel', 'cliente_id': cliente.id})
                db.session.commit()
        else:
            if alert.cliente_vinculado:
                cliente = alert.cliente_vinculado

        # 3. VERIFICAÇÕES DE APRENDIZADO
        if not cliente:
            return jsonify({'success': False, 'error': 'needs_learning'})
        
        if not cliente.teams_channel_id:
            return jsonify({'success': False, 'error': 'needs_channel', 'cliente_id': cliente.id})

        # 4. DISPARO NO TEAMS
        from azure_teams import enviar_mensagem_canal
        from azure_auth import decrypt_token, encrypt_token, TENANT_ID, CLIENT_ID, CLIENT_SECRET
        import requests
        
        token = session.get('azure_token')
        
        if not token and current_user.is_authenticated and current_user.ms_access_token:
            token = decrypt_token(current_user.ms_access_token)
            
        if not token:
            return jsonify({'success': False, 'error': 'AUTH_REQUIRED'}), 401
        
        hora_atual = datetime.now().hour
        saudacao = "Bom dia" if hora_atual < 12 else ("Boa tarde" if hora_atual < 18 else "Boa noite")
        
        urls_motores = {tc.team_name: tc.zabbix_url.rstrip('/') for tc in TeamZabbixConfig.query.all() if tc.zabbix_url}
        base_url_zabbix = urls_motores.get(alert.source_zabbix, ZABBIX_FRONT_URL)
        zabbix_link = f"{base_url_zabbix}/tr_events.php?triggerid={alert.objectid}&eventid={alert.eventid}"

        # 🎨 LAYOUT TEAMS
        card_html = f"""
        <div style="border: 1px solid rgba(128, 128, 128, 0.3); border-left: 4px solid #3b82f6; border-radius: 8px; font-family: 'Segoe UI', Tahoma, sans-serif; max-width: 600px;">
            <div style="padding: 12px 15px; border-bottom: 1px solid rgba(128, 128, 128, 0.3); background-color: rgba(59, 130, 246, 0.05); border-radius: 8px 8px 0 0;">
                <b style="font-size: 15px; color: #3b82f6;">📡 AVISO DE MONITORAMENTO: {cliente.nome}</b>
            </div>
            <div style="padding: 15px; font-size: 14px; line-height: 1.5;">
                <p style="margin-top: 0;"><b>Prezados, {saudacao}!</b></p>
                <p>Identificamos o alerta abaixo em nossa estrutura e nossa equipe de monitoramento já está verificando:</p>
                <div style="padding: 12px; border-left: 3px solid #94a3b8; background-color: rgba(148, 163, 184, 0.1); margin: 15px 0; border-radius: 0 6px 6px 0;">
                    <div style="margin-bottom: 8px;"><b>Host:</b> {alert.host}</div>
                    <div><b>Trigger:</b> {alert.name}</div>
                </div>
                <p style="font-style: italic; color: #64748b; font-size: 13px; margin-bottom: 0;">Ficamos à disposição para qualquer esclarecimento.</p>
                <div style="margin-top: 20px; padding-top: 15px; border-top: 1px dashed rgba(128, 128, 128, 0.3);">
                    <a href="{zabbix_link}" target="_blank" style="background-color: #3b82f6; color: white; padding: 8px 16px; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 12px; text-transform: uppercase; display: inline-block;">
                        🔗 Acessar no Zabbix
                    </a>
                </div>
            </div>
        </div>
        """
        
        sucesso, msg = enviar_mensagem_canal(token, cliente.teams_team_id, cliente.teams_channel_id, card_html)
        
        if not sucesso and ("expired" in str(msg).lower() or "401" in str(msg) or "invalidauthenticationtoken" in str(msg).lower()):
            if current_user.ms_refresh_token:
                try:
                    token_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
                    data_refresh = {
                        "client_id": CLIENT_ID,
                        "client_secret": CLIENT_SECRET,
                        "refresh_token": decrypt_token(current_user.ms_refresh_token),
                        "grant_type": "refresh_token"
                    }
                    r = requests.post(token_url, data=data_refresh, timeout=5)
                    if r.status_code == 200:
                        res = r.json()
                        novo_token = res["access_token"]
                        session['azure_token'] = novo_token
                        current_user.ms_access_token = encrypt_token(novo_token)
                        if "refresh_token" in res:
                            session['azure_refresh_token'] = res["refresh_token"]
                            current_user.ms_refresh_token = encrypt_token(res["refresh_token"])
                        db.session.commit()
                        
                        sucesso, msg = enviar_mensagem_canal(novo_token, cliente.teams_team_id, cliente.teams_channel_id, card_html)
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Erro na renovação silenciosa do Fast Ping: {e}")
                    
            if not sucesso:
                return jsonify({'success': False, 'error': 'AUTH_REQUIRED'}), 401
        
        if sucesso:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': str(msg)})

    except Exception as e: # <--- 🛡️ FECHAMENTO DA BLINDAGEM: Se qualquer erro estourar, o banco é salvo.
        db.session.rollback()
        logger.error(f"Falha critica no Fast Ping: {str(e)}")
        return jsonify({'success': False, 'error': 'Erro interno ao processar a requisição.'}), 500

# ==============================================================================
# DASHBOARD EXECUTIVO C-LEVEL E KPIS COMPARATIVOS
# ==============================================================================
@zabbix_bp.route('/zabbix/dashboard_executivo')
@login_required
def zabbix_corp_dashboard_view():
    """Renderiza a nova tela exclusiva de BI Corporativo"""
    # Usa a mesma permissão do painel tático para facilitar
    if not current_user.can('can_access_zabbix'): 
        return redirect(url_for('index'))
    return render_template('zabbix_corp_dashboard.html', user=current_user)
from sqlalchemy import func

@zabbix_bp.route('/api/zabbix/kpi_comparison')
@login_required
def api_zabbix_kpi_comparison():
    try:
        agora = datetime.now()
        
        # 1. Ranges de Tempo Exatos
        inicio_hoje = agora.replace(hour=0, minute=0, second=0, microsecond=0)
        
        ontem_agora = agora - timedelta(days=1)
        inicio_ontem = ontem_agora.replace(hour=0, minute=0, second=0, microsecond=0)
        fim_ontem = inicio_hoje - timedelta(seconds=1) # Fim do dia de ontem
        
        semana_agora = agora - timedelta(days=7)
        inicio_semana = semana_agora.replace(hour=0, minute=0, second=0, microsecond=0)
        fim_semana_exato = inicio_semana + timedelta(days=1, seconds=-1)

        # 2. Captura filtros passados pelo frontend
        req_groups = request.args.get('groups', '').strip()
        req_sevs = request.args.get('severities', '').strip()
        req_sector = request.args.get('sector', '').strip()

        # 3. Query Base (Busca alertas reais desses 3 dias específicos)
        query = ZabbixAlert.query.filter(
            or_(
                and_(ZabbixAlert.start_time >= inicio_hoje, ZabbixAlert.start_time <= agora),
                and_(ZabbixAlert.start_time >= inicio_ontem, ZabbixAlert.start_time <= fim_ontem),
                and_(ZabbixAlert.start_time >= inicio_semana, ZabbixAlert.start_time <= fim_semana_exato)
            )
        )

        # Filtro de Severidade Herdado
        if req_sevs and req_sevs != 'ALL':
            sev_list = [int(s) for s in req_sevs.split(',') if s.isdigit()]
            query = query.filter(ZabbixAlert.severity.in_(sev_list))
        else:
            query = query.filter(ZabbixAlert.severity.in_([4, 5]))

        # Filtro de Grupos Herdado
        if req_groups:
            group_list = [g.strip() for g in req_groups.split(',') if g.strip()]
            query = query.filter(ZabbixAlert.host_group.in_(group_list))

        # Filtro do Dropdown da Tela Executiva
        if req_sector and req_sector != 'ALL':
            query = query.filter(ZabbixAlert.host_group == req_sector)

        alertas = query.all()

        # 4. Variáveis de Retorno (Matemática 100% Real)
        hoje_count = 0
        ontem_count_ate_agora = 0 
        
        groups_today = {}
        groups_yesterday = {}
        
        hourly_today = [0] * 24
        hourly_yesterday = [0] * 24
        hourly_lastweek = [0] * 24

        # 5. Agrupamento e Separação por Dia e Hora
        for a in alertas:
            grp = a.host_group or "Geral"
            hora = a.start_time.hour

            if a.start_time >= inicio_hoje:
                hoje_count += 1
                groups_today[grp] = groups_today.get(grp, 0) + 1
                hourly_today[hora] += 1
            
            elif inicio_ontem <= a.start_time <= fim_ontem:
                hourly_yesterday[hora] += 1
                groups_yesterday[grp] = groups_yesterday.get(grp, 0) + 1
                # O comparador percentual de KPI considera apenas o volume até a hora atual para ser justo
                if a.start_time <= ontem_agora:
                    ontem_count_ate_agora += 1
            
            elif inicio_semana <= a.start_time <= fim_semana_exato:
                hourly_lastweek[hora] += 1

        return jsonify({
            "success": True,
            "today": hoje_count,
            "yesterday": ontem_count_ate_agora,
            "groups_today": groups_today,
            "groups_yesterday": groups_yesterday,
            "hourly_today": hourly_today,
            "hourly_yesterday": hourly_yesterday,
            "hourly_lastweek": hourly_lastweek
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    
# ==============================================================================
# MOTOR DA BLACKLIST (FILTRO DE RUÍDOS)
# ==============================================================================

@zabbix_bp.route('/api/zabbix/blacklist/preview', methods=['POST'])
@login_required
def api_zabbix_blacklist_preview():
    data = request.json
    trigger_pattern = data.get('trigger_pattern', '').strip()
    host_pattern = data.get('host_pattern', '').strip()
    req_host_groups = data.get('host_groups', [])

    if len(trigger_pattern) < 3:
        return jsonify({"success": False, "error": "Digite pelo menos 3 letras."}), 400

    # 🛡️ CAMADA 1: Descobre quais grupos são permitidos para o Squad deste usuário
    user_teams = current_user.teams.split(',') if current_user.teams else []
    equipe_usuario = user_teams[0].strip() if user_teams else 'Geral'
    
    allowed_groups = None
    if current_user.role.name != 'master_admin':
        preset_equipe = ZabbixFilterPreset.query.filter_by(equipe_dona=equipe_usuario).first()
        if preset_equipe and preset_equipe.grupos:
            allowed_groups = [g.strip().lower() for g in preset_equipe.grupos.split(',') if g.strip()]

    # 🚀 A MÁGICA: Busca 100% no banco LOCAL, instantâneo e sem tocar no Zabbix!
    query = ZabbixAlert.query.filter(ZabbixAlert.status == 'active')

    # Filtro ILIKE (case-insensitive direto no Postgres)
    query = query.filter(ZabbixAlert.name.ilike(f"%{trigger_pattern}%"))
    
    if host_pattern:
        query = query.filter(ZabbixAlert.host.ilike(f"%{host_pattern}%"))

    if req_host_groups:
        query = query.filter(ZabbixAlert.host_group.in_(req_host_groups))

    if allowed_groups:
        # Pega só os grupos permitidos se o cara não for admin
        query = query.filter(func.lower(ZabbixAlert.host_group).in_(allowed_groups))

    # Limita a apenas 5 resultados direto na query do banco de dados (Super Leve)
    alertas = query.limit(5).all()

    matches = []
    for a in alertas:
        matches.append({
            "host": a.host or 'Desconhecido',
            "trigger": a.name or 'Sem Título',
            "severity": a.severity or 0,
            "group": a.host_group or 'Geral'
        })

    return jsonify({"success": True, "matches": matches})

@zabbix_bp.route('/api/zabbix/blacklist/save', methods=['POST'])
@login_required
def api_zabbix_blacklist_save():
    data = request.json
    user_teams = current_user.teams.split(',') if current_user.teams else []
    equipe_usuario = user_teams[0].strip() if user_teams else 'Geral'
    
    if current_user.role.name == 'master_admin' and data.get('target_team'):
        equipe_usuario = data.get('target_team')

    trigger_pattern = data.get('trigger_pattern', '').strip()
    host_pattern = data.get('host_pattern', '').strip()
    duration = data.get('duration', 'forever') 
    
    # 🌟 NOVO: Captura os grupos em array e formata em string CSV
    grupos_selecionados = data.get('host_groups', [])
    grupos_str = ",".join(grupos_selecionados) if grupos_selecionados else None
    
    if not trigger_pattern:
        return jsonify({"success": False, "error": "Padrão de trigger obrigatório."}), 400

    expiration = None
    if duration == '1d': expiration = datetime.now() + timedelta(days=1)
    elif duration == '1w': expiration = datetime.now() + timedelta(days=7)
    elif duration == '1m': expiration = datetime.now() + timedelta(days=30)

    try:
            # Captura a lista de grupos checados e converte em texto separado por vírgulas
            grupos_selecionados = data.get('host_groups', [])
            grupos_str = ",".join(grupos_selecionados) if grupos_selecionados else None

            nova_regra = AlertBlacklist(
                team_name=equipe_usuario,
                trigger_pattern=trigger_pattern,
                host_pattern=host_pattern,
                expiration_date=expiration,
                created_by=current_user.id
            )
            # 🌟 Salva o escopo selecionado na tabela
            setattr(nova_regra, 'host_groups', grupos_str)
            
            db.session.add(nova_regra)
            db.session.commit()
            return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500  
    
# ==============================================================================
# VIEWS DA BLACKLIST (TELA DO ADMIN)
# ==============================================================================

@zabbix_bp.route('/admin/desk/blacklist', methods=['GET'])
@login_required
def admin_desk_blacklist():
    if not current_user.can('can_manage_zabbix_blacklist'):
        flash('Acesso negado.', 'danger')
        return redirect(url_for('index'))
    
    # 🌟 CORREÇÃO: O bloco de ALTER TABLE perigoso que travava o banco foi removido daqui!

    user_teams = current_user.teams.split(',') if current_user.teams else []
    equipe_usuario = user_teams[0].strip() if user_teams else 'Geral'
    agora = datetime.now()
    
    if current_user.role.name == 'master_admin':
        regras = AlertBlacklist.query.order_by(AlertBlacklist.created_at.desc()).all()
        times = Team.query.order_by(Team.name).all()
    else:
        regras = AlertBlacklist.query.filter_by(team_name=equipe_usuario).order_by(AlertBlacklist.created_at.desc()).all()
        times = []

    presets = ZabbixFilterPreset.query.all()
    grupos_por_equipe = {p.equipe_dona: p.grupos for p in presets if p.equipe_dona}

    # 📡 CAPTURA E ISOLA OS GRUPOS (MISTURA INTELIGENTE: Banco Local + Presets)
    try:
        # 🔥 A MÁGICA DA PERFORMANCE: Limitamos a varredura APENAS aos alertas ativos!
        grupos_db = db.session.query(ZabbixAlert.host_group).filter(
            ZabbixAlert.host_group.isnot(None),
            ZabbixAlert.status == 'active' 
        ).distinct().all()
        all_groups = [g[0] for g in grupos_db if g[0]]
    except Exception:
        all_groups = []

    if current_user.role.name != 'master_admin':
        # Caça o preset do time do analista logado
        preset_equipe = ZabbixFilterPreset.query.filter_by(equipe_dona=equipe_usuario).first()
        if preset_equipe and preset_equipe.grupos:
            grupos_zabbix = sorted([g.strip() for g in preset_equipe.grupos.split(',') if g.strip()])
        else:
            grupos_zabbix = sorted(all_groups)
    else:
        # Se for Master Admin, junta os grupos que já alertaram com TODOS os grupos cadastrados nos presets
        todos_presets = ZabbixFilterPreset.query.all()
        grupos_extra = []
        for p in todos_presets:
            if p.grupos:
                grupos_extra.extend([g.strip() for g in p.grupos.split(',') if g.strip()])
        
        grupos_zabbix = sorted(list(set(all_groups + grupos_extra)))

    return render_template('admin_blacklist.html', 
                           regras=regras, 
                           times=times, 
                           equipe_usuario=equipe_usuario, 
                           agora=agora, 
                           grupos_por_equipe=grupos_por_equipe,
                           grupos_zabbix=grupos_zabbix)

@zabbix_bp.route('/api/zabbix/blacklist/delete/<int:id>', methods=['POST'])
@login_required
def api_zabbix_blacklist_delete(id):
    if not current_user.can('can_manage_zabbix_blacklist'): # <--- NOVO
        return jsonify({'success': False}), 403
        
    regra = AlertBlacklist.query.get(id)
    if regra:
        db.session.delete(regra)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Regra não encontrada'}), 404

# ==============================================================================
# NOVA ROTA: MARCAR COMO ATUADO SEM TOCAR NO ZABBIX
# ==============================================================================
@zabbix_bp.route('/api/zabbix/mark_acted', methods=['POST'])
@login_required
def api_zabbix_mark_acted():
    try:
        d = request.json
        from sqlalchemy import tuple_
        pares = _parse_pares(d.get('event_ids', []))
        if not pares:
            return jsonify({"success": True})
            
        alerts = ZabbixAlert.query.filter(
            tuple_(ZabbixAlert.eventid, ZabbixAlert.source_zabbix).in_(pares)
        ).all()
        
        from collections import defaultdict
        alertas_por_source = defaultdict(list)
        
        for a in alerts:
            a.last_seen = datetime.now() # 🌟 MÁGICA
            
            if a.ack_user_id == current_user.id:
                mensagem_atual = a.ack_message.replace('[ATLAS BOT] Reconhecido. | ', '') if a.ack_message else 'Em Atendimento'
                if '[ATUADO]' not in mensagem_atual:
                    a.ack_message = f'[ATUADO] {mensagem_atual}'
                
                a.hidden_on_dash = False
            else:
                a.ack_user_id = current_user.id
                a.ack_message = '[ATUADO] Em Atendimento' 
                a.ack_at = datetime.now()
                a.hidden_on_dash = False
                
                alertas_por_source[a.source_zabbix or 'global'].append(a.eventid)
            
        db.session.commit()
        
        if alertas_por_source:
            from tasks import bg_zabbix_call_task
            
            # ✅ Montagem segura: Garante que o Global nunca será engolido por um dict vazio
            tokens_map = session.get('zbx_user_tokens', {}).copy()
            if session.get('zbx_user_token') and 'global' not in tokens_map:
                tokens_map['global'] = session.get('zbx_user_token')
                
            try:
                bg_zabbix_call_task.delay(dict(alertas_por_source), '[ATUADO] Em Atendimento', 6, tokens_map)
            except Exception as celery_err:
                logger.error(f"⚠️ Celery/Redis indisponível: {celery_err}")
            
        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    
@zabbix_bp.route('/debug/zabbix-force')
@login_required
def debug_zabbix_force():
    import traceback
    from flask import current_app
    
    logs = ["<div style='font-family: monospace; font-size: 14px; padding: 20px; background: #1e1e1e; color: #00ff00; line-height: 1.6; height: 100vh;'>"]
    logs.append("<h2 style='color: #fff;'>🔍 DIAGNÓSTICO PROFUNDO DO ZABBIX E BANCO DE DADOS</h2><hr>")
    
    # 1. DESTRAVANDO CADEADOS DE FORÇA BRUTA
    try:
        with db.engine.connect() as conn:
            # Libera qualquer trava morta que possa ter ficado no pool do Postgres
            conn.execute(text("SELECT pg_advisory_unlock_all()"))
            conn.commit()
            logs.append("🔓 [SUCESSO] Cadeados do banco de dados resetados e limpos.")
    except Exception as e:
        logs.append(f"⚠️ [AVISO] Falha ao tentar limpar cadeados: {e}")

    # 2. TESTE DE REDE E API COM O ZABBIX
    try:
        login_ok = zabbix_api.login_master()
        logs.append(f"📡 [REDE] Teste de Login Zabbix Global: {'✅ CONECTADO' if login_ok else '❌ FALHA DE LOGIN'}")
        
        if login_ok:
            probs = zabbix_api.get_enriched_problems(days=1)
            if probs is None:
                logs.append("❌ [API] Zabbix retornou 'None'. (O Zabbix demorou a responder ou o usuário não tem permissão de leitura).")
            else:
                logs.append(f"✅ [API] Comunicação perfeita! Zabbix Global respondeu com {len(probs)} alertas em aberto neste momento.")
    except Exception as e:
        logs.append(f"❌ [ERRO GRAVE DE REDE]: {str(e)}")
        logs.append(f"<pre style='color:red'>{traceback.format_exc()}</pre>")

    # 3. FORÇANDO A SINCRONIZAÇÃO MANUAL
    logs.append("<br>⏳ [ATLAS] Iniciando sincronização e injeção de dados no banco local...")
    try:
        start_time = time.time()
        # Chama a função que criamos ignorando o agendador
        resultado = sync_zabbix_to_db(current_app.app_context(), days=3)
        end_time = time.time()
        
        if resultado:
            logs.append(f"✅ [SUCESSO TOTAL] A sincronização rodou até o final em {round(end_time - start_time, 2)} segundos!")
            logs.append("➡️ Verifique seu Dashboard do Atlas, os alertas novos DEVEM estar lá agora.")
        else:
            logs.append("❌ [FALHA SILENCIOSA] A função retornou FALSE. (O script foi interrompido no meio. Verifique os logs do console para ver onde bateu).")
    except Exception as e:
        logs.append(f"❌ [ERRO CRÍTICO DURANTE A SINCRONIZAÇÃO]: {str(e)}")
        logs.append(f"<pre style='color:red'>{traceback.format_exc()}</pre>")
        
    logs.append("</div>")
    return "".join(logs) 

# ==============================================================================
# VIEWS DA VIA EXPRESSA (PRIORIDADE ALTA)
# ==============================================================================
@zabbix_bp.route('/admin/desk/priority', methods=['GET'])
@login_required
def admin_desk_priority():
    # APAGUE OU COMENTE ESTAS 3 LINHAS:
    # if not current_user.can('can_manage_zabbix_blacklist'):
    #     flash('Acesso negado.', 'danger')
    #     return redirect(url_for('index'))

    user_teams = current_user.teams.split(',') if current_user.teams else []
    equipe_usuario = user_teams[0].strip() if user_teams else 'Geral'
    
    from models import AlertPriorityRule, Team, ZabbixFilterPreset, ZabbixAlert
    
    if current_user.role.name == 'master_admin':
        regras = AlertPriorityRule.query.order_by(AlertPriorityRule.created_at.desc()).all()
        times = Team.query.order_by(Team.name).all()
    else:
        regras = AlertPriorityRule.query.filter_by(team_name=equipe_usuario).order_by(AlertPriorityRule.created_at.desc()).all()
        times = []

    # Mesma lógica da blacklist para puxar os grupos de host
    try:
        grupos_db = db.session.query(ZabbixAlert.host_group).filter(
            ZabbixAlert.host_group.isnot(None),
            ZabbixAlert.status == 'active' 
        ).distinct().all()
        all_groups = [g[0] for g in grupos_db if g[0]]
    except Exception:
        all_groups = []

    if current_user.role.name != 'master_admin':
        preset_equipe = ZabbixFilterPreset.query.filter_by(equipe_dona=equipe_usuario).first()
        if preset_equipe and preset_equipe.grupos:
            grupos_zabbix = sorted([g.strip() for g in preset_equipe.grupos.split(',') if g.strip()])
        else:
            grupos_zabbix = sorted(all_groups)
    else:
        todos_presets = ZabbixFilterPreset.query.all()
        grupos_extra = []
        for p in todos_presets:
            if p.grupos:
                grupos_extra.extend([g.strip() for g in p.grupos.split(',') if g.strip()])
        grupos_zabbix = sorted(list(set(all_groups + grupos_extra)))

    return render_template('admin_priority.html', regras=regras, times=times, equipe_usuario=equipe_usuario, grupos_zabbix=grupos_zabbix)

@zabbix_bp.route('/api/zabbix/priority/save', methods=['POST'])
@login_required
def api_zabbix_priority_save():
    from models import AlertPriorityRule, ZabbixAlert
    data = request.json
    rule_id = data.get('id')  # 👈 CAPTURA O ID DA REGRA (SE FOR EDIÇÃO)
    user_teams = current_user.teams.split(',') if current_user.teams else []
    equipe_usuario = user_teams[0].strip() if user_teams else 'Geral'
    
    if current_user.role.name == 'master_admin' and data.get('target_team'):
        equipe_usuario = data.get('target_team')

    trigger_pattern = data.get('trigger_pattern', '').strip()
    host_pattern = data.get('host_pattern', '').strip()
    grupos_selecionados = data.get('host_groups', [])
    grupos_str = ",".join(grupos_selecionados) if grupos_selecionados else None
    
    if not trigger_pattern:
        return jsonify({"success": False, "error": "Padrão de trigger obrigatório."}), 400

    try:
        if rule_id:
            # 🌟 ATUALIZA REGRA EXISTENTE
            nova_regra = AlertPriorityRule.query.get(rule_id)
            if not nova_regra:
                return jsonify({"success": False, "error": "Regra não encontrada."}), 404
            nova_regra.team_name = equipe_usuario
            nova_regra.trigger_pattern = trigger_pattern
            nova_regra.host_pattern = host_pattern
            nova_regra.host_groups = grupos_str
        else:
            # 🌟 CRIA NOVA REGRA
            nova_regra = AlertPriorityRule(
                team_name=equipe_usuario,
                trigger_pattern=trigger_pattern,
                host_pattern=host_pattern,
                host_groups=grupos_str,
                created_by=current_user.id
            )
            db.session.add(nova_regra)
        
        # 🌟 UPDATE RETROATIVO: Marca/atualiza na hora os alertas ativos que já estão abertos
        query_update = db.session.query(ZabbixAlert).filter(
            ZabbixAlert.status == 'active',
            ZabbixAlert.name.ilike(f"%{trigger_pattern}%")
        )
        if host_pattern:
            query_update = query_update.filter(ZabbixAlert.host.ilike(f"%{host_pattern}%"))
        if grupos_selecionados:
            query_update = query_update.filter(ZabbixAlert.host_group.in_(grupos_selecionados))

        query_update.update({
            'is_priority': True,
            'last_seen': datetime.now(), 
            'buffer_expires_at': datetime.now() - timedelta(minutes=1)
        }, synchronize_session=False)

        db.session.commit()
        redis_db.delete("zabbix_dash_hash")
        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500

@zabbix_bp.route('/api/zabbix/priority/delete/<int:id>', methods=['POST'])
@login_required
def api_zabbix_priority_delete(id):
    # APAGUE OU COMENTE ESTAS 2 LINHAS:
    # if not current_user.can('can_manage_zabbix_blacklist'): 
    #     return jsonify({'success': False}), 403
        
    from models import AlertPriorityRule, ZabbixAlert
    regra = AlertPriorityRule.query.get(id)
    if regra:
        trig_pat = regra.trigger_pattern
        host_pat = regra.host_pattern
        
        db.session.delete(regra)
        db.session.commit()

        # 🌟 VARREDURA RETROATIVA: Remove a flag VIP dos alertas ativos se não baterem com nenhuma outra regra restante
        regras_restantes = AlertPriorityRule.query.filter_by(is_active=True).all()
        
        # 👇 CORREÇÃO: Busca TODOS os alertas que estão VIPs hoje para reavaliar a malha inteira
        query_afetados = db.session.query(ZabbixAlert).filter(
            ZabbixAlert.status == 'active',
            ZabbixAlert.is_priority == True
        )

        for alert in query_afetados.all():
            ainda_prio = False
            for rp in regras_restantes:
                tp = (rp.trigger_pattern or '').lower()
                hp = (rp.host_pattern or '').lower()
                gp = [g.strip().lower() for g in rp.host_groups.split(',') if g.strip()] if getattr(rp, 'host_groups', None) else []
                
                if gp and (alert.host_group or '').lower() not in gp:
                    continue
                if tp and tp in (alert.name or '').lower():
                    if not hp or hp in (alert.host or '').lower():
                        ainda_prio = True
                        break
            if not ainda_prio:
                alert.is_priority = False
                alert.last_seen = datetime.now() 

        db.session.commit()
        redis_db.delete("zabbix_dash_hash") # 👈 MÁGICA: Força o WebSocket a atualizar a tela na hora
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Regra não encontrada'}), 404 
import uuid

@zabbix_bp.route('/api/zabbix/manual_group', methods=['POST'])
@login_required
def api_zabbix_manual_group():
    try:
        data = request.json
        pares = _parse_pares(data.get('event_ids', []))
        
        if not pares:
            return jsonify({"success": False, "error": "Nenhum alerta selecionado."})

        # Gera um ID único para esse grupo
        novo_grupo_id = f"grp_{uuid.uuid4().hex[:8]}"

        # Atualiza todos os alertas selecionados colocando o mesmo ID neles
        from sqlalchemy import tuple_
        db.session.query(ZabbixAlert).filter(
            tuple_(ZabbixAlert.eventid, ZabbixAlert.source_zabbix).in_(pares)
        ).update({
            'manual_group_id': novo_grupo_id,
            'last_seen': datetime.now() # Força a tela a atualizar na hora
        }, synchronize_session=False)

        db.session.commit()
        return jsonify({"success": True, "group_id": novo_grupo_id})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
