from __future__ import annotations

from datetime import datetime
import json

import pandas as pd
import plotly.express as px
import streamlit as st

from cybersheid.data import (SEVERITIES, demo_series, get_detections, save_detection,
                             update_status)
from cybersheid.dataset import (DATASET_PATH, NUMERIC_FEATURES, dataset_distribution,
                                load_dataset, save_uploaded_dataset, dataset_status)
from cybersheid.model import feature_names, load_model, predict, save_uploaded_model

NAV = ["Dashboard", "Threat Analysis", "New Detection", "Reports", "Settings"]
COLORS = {"Critical": "#f04459", "High": "#ff9b37", "Medium": "#f4c542", "Low": "#22b8d4"}
PLOT_LAYOUT = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#071d31", font_color="#d7e7f7",
                   margin=dict(l=12, r=12, t=25, b=12), xaxis=dict(gridcolor="#153650"), yaxis=dict(gridcolor="#153650"))


def severity_for_label(label: str) -> str:
    label = str(label).lower()
    if label in {"normal", "benign", "normal traffic"}: return "Low"
    if any(word in label for word in ("ddos", "ransom", "malware", "sqlinjection", "dataexfiltration")): return "Critical"
    if any(word in label for word in ("dos", "brute", "botnet", "portscan", "dnstunneling", "xss")): return "High"
    return "Medium"


def risk_for(label: str, confidence: float | None) -> int:
    if severity_for_label(label) == "Low": return 8
    base = {"Critical": 92, "High": 76, "Medium": 58}.get(severity_for_label(label), 58)
    if confidence is not None:
        return max(base - 12, min(98, round(base * .55 + confidence * 45)))
    return base


def inject_css():
    st.markdown("""<style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap');
    :root{--navy:#061525;--panel:#0a2136;--line:#173b59;--text:#e9f2fc;--muted:#91a9c1}
    html,body,[class*="css"]{font-family:'DM Sans',sans-serif}.stApp{background:radial-gradient(ellipse at 70% -15%,#0b2b48 0,#061525 55%);color:var(--text)}
    [data-testid="stSidebar"]{background:#071a2c;border-right:1px solid #163650}[data-testid="stSidebar"]>div{padding-top:1rem}
    [data-testid="stHeader"]{background:rgba(5,19,33,.88);border-bottom:1px solid #163650}.block-container{padding-top:1.45rem;padding-bottom:2rem;max-width:1450px}
    .brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:19px;color:#f4f8ff;padding:10px 6px 24px}.shield{width:30px;height:34px;background:linear-gradient(145deg,#38a2ff,#0658b0);clip-path:polygon(50% 0,94% 16%,90% 65%,50% 100%,10% 65%,6% 16%);display:grid;place-items:center;color:white;font-size:16px}
    .topbar{display:flex;justify-content:space-between;align-items:center;background:rgba(8,29,49,.92);border:1px solid #143653;border-radius:12px;padding:10px 16px;margin:0 0 20px}
    .eyebrow{color:#92abc2;font-size:13px;margin-top:-8px;margin-bottom:18px}h1{font-size:27px!important;letter-spacing:-.4px;color:#f2f7ff!important}.metric{background:linear-gradient(140deg,#0d2a44,#091f34);border:1px solid #173b59;border-radius:12px;padding:15px 16px;min-height:96px}.metric-label{font-size:12px;color:#aec2d5}.metric-value{font-size:26px;font-weight:700;color:#f5f9ff;margin-top:3px}.metric-foot{font-size:11px;color:#7f9bb5;margin-top:1px}
    .card{background:linear-gradient(145deg,#0b253d,#081d31);border:1px solid #173a56;border-radius:12px;padding:16px;margin-bottom:14px}.section-title{font-size:15px;font-weight:700;color:#eaf4ff;margin-bottom:10px}.muted{color:#91a9c1;font-size:12px}.status-dot{color:#21d79b}
    .stButton>button{background:linear-gradient(90deg,#0879df,#138bf4);border:1px solid #299aff;color:#fff;border-radius:7px;font-weight:600}.stDownloadButton>button{background:#0b2c49;color:#e6f4ff;border:1px solid #1d5278;border-radius:7px}
    div[data-baseweb="select"]>div,input,textarea{background:#0a2238!important;border-color:#20435f!important;color:#e9f2fc!important}[data-testid="stDataFrame"]{border:1px solid #173b59;border-radius:10px;overflow:hidden}.stTabs [data-baseweb="tab-list"]{gap:20px;border-bottom:1px solid #173b59}.stTabs [aria-selected="true"]{color:#42a8ff!important}
    @media(max-width:700px){.block-container{padding:1rem .75rem}.metric{padding:12px;min-height:85px}.metric-value{font-size:22px}.topbar{padding:9px 10px}}
    </style>""", unsafe_allow_html=True)


def shell():
    with st.sidebar:
        st.markdown('<div class="brand"><span class="shield">⬡</span> CYBERSHEID</div>', unsafe_allow_html=True)
        selection = st.radio("Navigation", NAV, label_visibility="collapsed", key="page")
        st.markdown("<div style='height:35vh'></div><div class='muted'>SECURITY CONSOLE<br>Dataset-aware · v2.0</div>", unsafe_allow_html=True)
    st.markdown('<div class="topbar"><span class="muted">☰ &nbsp; Workspace / <b style="color:#eaf4ff">'+selection+'</b></span><span class="user-chip">♧ &nbsp; ◉ &nbsp; Deekshita⌄</span></div>', unsafe_allow_html=True)
    return selection


def heading(title, subtitle):
    st.title(title); st.markdown(f'<div class="eyebrow">{subtitle}</div>', unsafe_allow_html=True)


def metric(label, value, icon, color, foot=""):
    st.markdown(f'<div class="metric"><div style="display:flex;gap:9px;align-items:center"><span style="color:{color};font-size:17px">{icon}</span><span class="metric-label">{label}</span></div><div class="metric-value">{value}</div><div class="metric-foot">{foot}</div></div>', unsafe_allow_html=True)


def chart_theme(fig, height=280):
    fig.update_layout(**PLOT_LAYOUT, height=height, legend=dict(orientation="h", y=-.2, font=dict(size=10))); return fig


def dashboard():
    df_db = get_detections(); dataset = load_dataset()
    heading("Security Dashboard", "Monitor threat records, dataset coverage and system activity.")
    demo = df_db["origin"].eq("DEMO").all() if not df_db.empty else True
    if demo: st.info("Demonstration database view: synthetic records are not live monitoring or model predictions.", icon="ℹ️")
    critical=int((df_db.severity=="Critical").sum()) if not df_db.empty else 0
    high=int((df_db.severity=="High").sum()) if not df_db.empty else 0
    medium=int((df_db.severity=="Medium").sum()) if not df_db.empty else 0
    cols=st.columns(4)
    for col,args in zip(cols,[("Critical Threats",critical,"✹",COLORS["Critical"]),("High Threats",high,"▲",COLORS["High"]),("Medium Threats",medium,"⬟",COLORS["Medium"]),("Total Threats",len(df_db),"◉","#38a2ff")]):
        with col: metric(*args,foot="Recorded detections")
    left,right=st.columns([1.25,1])
    with left:
        st.markdown('<div class="card"><div class="section-title">Threat Activity</div><div class="muted">Synthetic 7-day database trend</div>',unsafe_allow_html=True)
        series=demo_series(7).melt("Date",var_name="Severity",value_name="Threats")
        fig=px.line(series,x="Date",y="Threats",color="Severity",color_discrete_map=COLORS,markers=True)
        st.plotly_chart(chart_theme(fig,250),use_container_width=True,config={"displayModeBar":False}); st.markdown('</div>',unsafe_allow_html=True)
    with right:
        st.markdown('<div class="card"><div class="section-title">System Status</div>',unsafe_allow_html=True)
        model,_=load_model()
        for name,state in [("Detection Service","Ready"),("SQLite Database","Connected"),("Model Integration","Configured" if model is not None else "Not connected"),("Dataset",dataset_status())]:
            st.markdown(f'<div style="display:flex;justify-content:space-between;padding:11px 2px;border-bottom:1px solid #153650"><span>{name}</span><span class="muted"><span class="status-dot">●</span> &nbsp;{state}</span></div>',unsafe_allow_html=True)
        st.markdown('</div>',unsafe_allow_html=True)
        st.markdown('<div class="card"><div class="section-title">Recent Threats</div>',unsafe_allow_html=True)
        show=df_db.head(5)[["threat","severity","source_ip","risk","status"]].rename(columns={"threat":"Threat","severity":"Severity","source_ip":"Source","risk":"Risk","status":"Status"})
        st.dataframe(show,hide_index=True,use_container_width=True,height=205); st.markdown('</div>',unsafe_allow_html=True)


def threat_analysis():
    df=get_detections(); heading("Threat Analysis", "Search, inspect and resolve detected threats.")
    search,sev,status_col=st.columns([2,1.1,1.1])
    with search: query=st.text_input("Search threats",placeholder="Threat, category or source IP")
    with sev: severity=st.selectbox("Severity",["All Severities"]+SEVERITIES)
    with status_col: state=st.selectbox("Status",["All Statuses","Open","Investigating","Resolved"])
    filtered=df.copy()
    if query: filtered=filtered[filtered.astype(str).apply(lambda c:c.str.contains(query,case=False,na=False)).any(axis=1)]
    if severity!="All Severities": filtered=filtered[filtered.severity==severity]
    if state!="All Statuses": filtered=filtered[filtered.status==state]
    st.caption(f"{len(filtered)} records · DEMO marks synthetic UI records; PREDICTION marks saved-model output.")
    if filtered.empty: st.info("No threats match the selected filters."); return
    display=filtered[["id","threat","severity","category","risk","source_ip","status","detected_at","origin"]].copy()
    display["detected_at"]=pd.to_datetime(display.detected_at).dt.strftime("%Y-%m-%d %H:%M")
    display=display.rename(columns={"id":"ID","threat":"Threat","severity":"Severity","category":"Category","risk":"Risk","source_ip":"Source IP","status":"Status","detected_at":"Detected","origin":"Type"})
    st.dataframe(display,hide_index=True,use_container_width=True,height=350)
    selected=st.selectbox("Open threat detail",filtered.id.astype(int).tolist(),format_func=lambda x:f"#{x} · {df.loc[df.id==x,'threat'].iloc[0]}")
    item=df[df.id==selected].iloc[0]
    with st.expander("Threat details",expanded=True):
        a,b,c,d=st.columns(4)
        with a: metric("Risk Score",f"{item.risk} / 100","◉","#fb6574")
        with b: metric("Status",item.status,"●","#ffb14d")
        with c: metric("Category",item.category,"⌕","#40a5ff")
        with d: metric("Detection Type",item.origin,"◇","#29d7aa")
        st.write(f"**Threat:** {item.threat} · **Source:** `{item.source_ip}` · **Detected:** {item.detected_at}")
        st.caption(item.details or "No additional evidence attached.")
        if item.origin=="PREDICTION": st.caption(f"Model confidence: {item.confidence:.1%}" if pd.notna(item.confidence) else "Model does not expose confidence.")
        new_status=st.selectbox("Update status",["Open","Investigating","Resolved"],index=["Open","Investigating","Resolved"].index(item.status) if item.status in ["Open","Investigating","Resolved"] else 0)
        if st.button("Save status",key=f"save_{selected}"):
            update_status(int(selected),new_status); st.success("Status updated."); st.rerun()


def new_detection():
    heading("New Detection", "Enter all 13 dataset features and run your saved Random Forest model.")
    model,message=load_model()
    if model is None: st.warning(f"Model unavailable — {message}")
    else: st.success(message)
    dataset=load_dataset()
    protocols=["TCP","UDP","ICMP"]
    if dataset is not None:
        protocols=sorted(dataset.protocol.dropna().astype(str).unique())
    names=feature_names(model)
    st.caption("Fields use the same names as threat_detection_52000.csv. Text and protocol values are preserved for categorical pipelines.")
    with st.form("detection_form"):
        c1,c2,c3=st.columns(3)
        with c1:
            src_ip=st.text_input("src_ip","192.168.1.10")
            protocol=st.selectbox("protocol",protocols)
            src_port=st.number_input("src_port",0,65535,49152)
            dst_port=st.number_input("dst_port",0,65535,443)
        with c2:
            dst_ip=st.text_input("dst_ip","10.0.0.5")
            packet_count=st.number_input("packet_count",0.0,1000000.0,100.0,step=1.0)
            bytes_sent=st.number_input("bytes_sent",0.0,10000000.0,15000.0,step=100.0)
            duration_sec=st.number_input("duration_sec",0.0,100000.0,5.0)
        with c3:
            failed_connections=st.number_input("failed_connections",0.0,100000.0,5.0,step=1.0)
            login_attempts=st.number_input("login_attempts",0.0,100000.0,3.0,step=1.0)
            connection_rate=st.number_input("connection_rate",0.0,100000.0,50.0)
            avg_payload_size=st.number_input("avg_payload_size",0.0,1000000.0,250.0)
            flag_count=st.number_input("flag_count",0.0,100000.0,8.0,step=1.0)
        submitted=st.form_submit_button("Analyze & Save",use_container_width=True)
    if submitted:
        if model is None:
            st.error("No prediction was generated because no saved model is connected.")
        else:
            raw={"src_ip":src_ip,"dst_ip":dst_ip,"protocol":protocol,"src_port":src_port,"dst_port":dst_port,"packet_count":packet_count,"bytes_sent":bytes_sent,"duration_sec":duration_sec,"failed_connections":failed_connections,"login_attempts":login_attempts,"connection_rate":connection_rate,"avg_payload_size":avg_payload_size,"flag_count":flag_count}
            try:
                result=predict(model,raw)
                label=result["category"]; severity=severity_for_label(label); risk=risk_for(label,result["confidence"])
                confidence=result["confidence"]
                save_detection(label,severity,label,risk,src_ip,"PREDICTION",confidence,f"Saved-model prediction: {result['label']} · protocol={protocol} · dst_ip={dst_ip}")
                st.success("Prediction saved to SQLite.")
                st.markdown('<div class="card"><div class="section-title">Prediction Result</div>',unsafe_allow_html=True)
                a,b,c=st.columns(3)
                with a: metric("Predicted Threat",label,"◉","#4aa7ff")
                with b: metric("Risk Score",f"{risk}/100","▲",COLORS[severity])
                with c: metric("Confidence","N/A" if confidence is None else f"{confidence:.1%}","✓","#28d3a1")
                st.markdown('</div>',unsafe_allow_html=True)
            except Exception as exc:
                st.error(f"Prediction failed: {exc}")


def reports():
    heading("Model Evaluation & Security Reports", "Real dataset analytics and downloadable detection history.")
    dataset=load_dataset()
    upload=st.file_uploader("Upload threat_detection_52000.csv",type=["csv"])
    if upload:
        try:
            dataset,path=save_uploaded_dataset(upload); st.success(f"Dataset uploaded and validated: {path} · {len(dataset):,} records")
        except Exception as exc: st.error(str(exc)); return
    if dataset is None:
        st.warning("Upload the CSV to calculate dataset distribution. Evaluation metrics remain available only when your saved model has an external test-set report.")
    else:
        dist=dataset_distribution(dataset)
        c1,c2,c3,c4=st.columns(4)
        with c1: metric("Dataset Records",f"{len(dataset):,}","▦","#4aa7ff")
        with c2: metric("Threat Classes",dataset.label.nunique(),"◆","#ffb43c")
        with c3: metric("Normal Records",int(dataset.label.astype(str).str.lower().eq("normal").sum()),"✓","#28d3a1")
        with c4: metric("Attack Records",int(dataset.label.astype(str).str.lower().ne("normal").sum()),"!","#f04459")
        left,right=st.columns([1.1,1])
        with left:
            st.markdown('<div class="card"><div class="section-title">Threat Distribution</div>',unsafe_allow_html=True)
            fig=px.bar(dist.head(12),x="Records",y="Threat Category",orientation="h",color="Records",color_continuous_scale=["#0e5aa3","#35a4ff"])
            fig.update_layout(coloraxis_showscale=False); st.plotly_chart(chart_theme(fig,330),use_container_width=True,config={"displayModeBar":False}); st.markdown('</div>',unsafe_allow_html=True)
        with right:
            st.markdown('<div class="card"><div class="section-title">Dataset Class Share</div>',unsafe_allow_html=True)
            fig=px.pie(dist.head(12),values="Records",names="Threat Category",hole=.58); st.plotly_chart(chart_theme(fig,330),use_container_width=True,config={"displayModeBar":False}); st.markdown('</div>',unsafe_allow_html=True)
        with st.expander("Preview dataset",expanded=False): st.dataframe(dataset.head(100),hide_index=True,use_container_width=True,height=280)
    st.markdown('<div class="card"><div class="section-title">Model Evaluation Status</div>',unsafe_allow_html=True)
    st.info("No held-out test evaluation is claimed until metrics and a confusion matrix are calculated from labeled data or supplied by the project. The app does not retrain the model.")
    st.markdown('</div>',unsafe_allow_html=True)
    df=get_detections()
    st.download_button("Download detections CSV",df.to_csv(index=False).encode("utf-8"),file_name=f"cybersheid-detections-{datetime.now():%Y%m%d}.csv",mime="text/csv")
    report={"generated_at":datetime.now().isoformat(timespec="seconds"),"dataset_status":dataset_status(),"evaluation":"Not available: no held-out test metrics supplied","detections":df.to_dict(orient="records")}
    st.download_button("Download security report JSON",json.dumps(report,indent=2,default=str),file_name=f"cybersheid-report-{datetime.now():%Y%m%d}.json",mime="application/json")


def settings():
    heading("Alert & Resolution Analytics", "Monitor alert status and application configuration.")
    df=get_detections(); total=len(df); resolved=int((df.status=="Resolved").sum()) if total else 0; pending=total-resolved
    cols=st.columns(4)
    for col,args in zip(cols,[("Total Alerts",total,"✦","#9166ff"),("Resolved Alerts",resolved,"✓","#26d7a1"),("Pending Alerts",pending,"◉","#ffb432"),("Avg. Resolution Time","—","◷","#38a2ff")]):
        with col: metric(*args,foot="Recorded detections" if args[0]!="Avg. Resolution Time" else "Resolution timestamps not stored")
    left,mid,right=st.columns([1,1,1.2])
    with left:
        st.markdown('<div class="card"><div class="section-title">Alert Status</div>',unsafe_allow_html=True)
        counts=df.status.value_counts().rename_axis("Status").reset_index(name="Alerts") if not df.empty else pd.DataFrame(columns=["Status","Alerts"])
        if not counts.empty:
            fig=px.pie(counts,values="Alerts",names="Status",hole=.6,color_discrete_sequence=["#25c99a","#f7bd33","#1687ee"]); st.plotly_chart(chart_theme(fig,235),use_container_width=True,config={"displayModeBar":False})
        st.markdown('</div>',unsafe_allow_html=True)
    with mid:
        st.markdown('<div class="card"><div class="section-title">Alerts by Severity</div>',unsafe_allow_html=True)
        counts=df.severity.value_counts().reindex(SEVERITIES,fill_value=0).rename_axis("Severity").reset_index(name="Alerts")
        fig=px.bar(counts,x="Severity",y="Alerts",color="Severity",color_discrete_map=COLORS); st.plotly_chart(chart_theme(fig,235),use_container_width=True,config={"displayModeBar":False}); st.markdown('</div>',unsafe_allow_html=True)
    with right:
        st.markdown('<div class="card"><div class="section-title">Resolution Records</div><div class="muted">Status updates are saved in SQLite.</div>',unsafe_allow_html=True)
        st.dataframe(df[["threat","severity","status","origin"]].head(6).rename(columns={"threat":"Threat","severity":"Severity","status":"Status","origin":"Type"}),hide_index=True,use_container_width=True,height=235); st.markdown('</div>',unsafe_allow_html=True)
    st.markdown('<div class="card"><div class="section-title">Application & Model Information</div>',unsafe_allow_html=True)
    model,message=load_model()
    st.write("**Application:** CYBERSHEID · Dataset-aware Streamlit security console")
    st.write(f"**Dataset:** {dataset_status()}")
    st.write(f"**Saved model:** {'Connected' if model is not None else 'Not connected'} · {message}")

    model_upload = st.file_uploader("Upload existing Random Forest model", type=["joblib", "pkl", "pickle"], key="model_upload")
    if model_upload:
        try:
            loaded, saved_path = save_uploaded_model(model_upload)
            st.success(f"Model uploaded and validated: {saved_path}")
            st.caption(f"Feature fields detected: {', '.join(feature_names(loaded))}")
        except Exception as exc:
            st.error(f"Model upload failed: {exc}")

    st.caption("The app analyzes the 13 dataset fields entered manually or supplied by a trained model-ready pipeline. It does not monitor live traffic, capture packets or block attacks.")
    st.markdown('</div>',unsafe_allow_html=True)


def run():
    inject_css(); page=shell(); {"Dashboard":dashboard,"Threat Analysis":threat_analysis,"New Detection":new_detection,"Reports":reports,"Settings":settings}[page]()
