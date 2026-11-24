from __future__ import annotations

from datetime import datetime
import json

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from cybersheid.data import (CATEGORIES, SEVERITIES, demo_metrics, demo_series, get_detections,
                             save_detection, update_status)
from cybersheid.model import feature_names, load_model, predict

NAV = ["Dashboard", "Threat Analysis", "New Detection", "Reports", "Settings"]
COLORS = {"Critical": "#f04459", "High": "#ff9b37", "Medium": "#f4c542", "Low": "#22b8d4"}
PLOT_LAYOUT = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#071d31", font_color="#d7e7f7",
                   margin=dict(l=12, r=12, t=25, b=12), xaxis=dict(gridcolor="#153650"), yaxis=dict(gridcolor="#153650"))


def inject_css():
    st.markdown("""<style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap');
    :root{--navy:#061525;--panel:#0a2136;--panel2:#0b2943;--line:#173b59;--text:#e9f2fc;--muted:#91a9c1;--blue:#1388f5}
    html,body,[class*="css"]{font-family:'DM Sans',sans-serif} .stApp{background:radial-gradient(ellipse at 70% -15%,#0b2b48 0,#061525 55%);color:var(--text)}
    [data-testid="stSidebar"]{background:#071a2c;border-right:1px solid #163650} [data-testid="stSidebar"]>div{padding-top:1rem}
    [data-testid="stHeader"]{background:rgba(5,19,33,.88);border-bottom:1px solid #163650}
    .brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:19px;color:#f4f8ff;padding:10px 6px 24px}
    .shield{width:30px;height:34px;background:linear-gradient(145deg,#38a2ff,#0658b0);clip-path:polygon(50% 0,94% 16%,90% 65%,50% 100%,10% 65%,6% 16%);display:grid;place-items:center;color:white;font-size:16px}
    .topbar{display:flex;justify-content:space-between;align-items:center;background:rgba(8,29,49,.92);border:1px solid #143653;border-radius:12px;padding:10px 16px;margin:0 0 20px}
    .user-chip{color:#dcecff;font-size:13px}.eyebrow{color:#92abc2;font-size:13px;margin-top:-8px;margin-bottom:18px}
    h1{font-size:27px!important;letter-spacing:-.4px;color:#f2f7ff!important} h2,h3{color:#eaf3ff!important}
    .metric{background:linear-gradient(140deg,#0d2a44,#091f34);border:1px solid #173b59;border-radius:12px;padding:15px 16px;min-height:96px}
    .metric-label{font-size:12px;color:#aec2d5}.metric-value{font-size:26px;font-weight:700;color:#f5f9ff;margin-top:3px}.metric-foot{font-size:11px;color:#7f9bb5;margin-top:1px}
    .card{background:linear-gradient(145deg,#0b253d,#081d31);border:1px solid #173a56;border-radius:12px;padding:16px;margin-bottom:14px}
    .section-title{font-size:15px;font-weight:700;color:#eaf4ff;margin-bottom:10px}.muted{color:#91a9c1;font-size:12px}
    .pill{display:inline-block;border-radius:5px;padding:3px 8px;font-size:11px;font-weight:600;background:#173650;color:#d9eaff}
    .status-dot{color:#21d79b}.stButton>button{background:linear-gradient(90deg,#0879df,#138bf4);border:1px solid #299aff;color:#fff;border-radius:7px;font-weight:600}
    .stButton>button:hover{background:#1674cb;border-color:#4ba9ff;color:white}.stDownloadButton>button{background:#0b2c49;color:#e6f4ff;border:1px solid #1d5278;border-radius:7px}
    div[data-baseweb="select"]>div,input,textarea{background:#0a2238!important;border-color:#20435f!important;color:#e9f2fc!important}
    [data-testid="stDataFrame"]{border:1px solid #173b59;border-radius:10px;overflow:hidden}
    .stTabs [data-baseweb="tab-list"]{gap:20px;border-bottom:1px solid #173b59}.stTabs [data-baseweb="tab"]{color:#9cb4ca}
    .stTabs [aria-selected="true"]{color:#42a8ff!important}.block-container{padding-top:1.45rem;padding-bottom:2rem;max-width:1450px}
    @media(max-width:700px){.block-container{padding:1rem .75rem}.metric{padding:12px;min-height:85px}.metric-value{font-size:22px}.topbar{padding:9px 10px}}
    </style>""", unsafe_allow_html=True)


def shell():
    with st.sidebar:
        st.markdown('<div class="brand"><span class="shield">⬡</span> CYBERSHEID</div>', unsafe_allow_html=True)
        selection = st.radio("Navigation", NAV, label_visibility="collapsed", key="page")
        st.markdown("<div style='height:35vh'></div><div class='muted'>SECURITY CONSOLE<br>Demo environment · v1.0</div>", unsafe_allow_html=True)
    st.markdown('<div class="topbar"><span class="muted">☰ &nbsp; Workspace / <b style="color:#eaf4ff">'+selection+'</b></span><span class="user-chip">♧ &nbsp; ◉ &nbsp; Deekshita⌄</span></div>', unsafe_allow_html=True)
    return selection


def heading(title, subtitle):
    st.title(title)
    st.markdown(f'<div class="eyebrow">{subtitle}</div>', unsafe_allow_html=True)


def metric(label, value, icon, color, foot=""):
    st.markdown(f'<div class="metric"><div style="display:flex;gap:9px;align-items:center"><span style="color:{color};font-size:17px">{icon}</span><span class="metric-label">{label}</span></div><div class="metric-value">{value}</div><div class="metric-foot">{foot}</div></div>', unsafe_allow_html=True)


def chart_theme(fig, height=280):
    fig.update_layout(**PLOT_LAYOUT, height=height, legend=dict(orientation="h", y=-.2, font=dict(size=10)))
    return fig


def dashboard():
    df = get_detections()
    heading("Security Dashboard", "Monitor detected threats and system activity.")
    if not df.empty and (df.origin == "DEMO").all():
        st.info("Demonstration view: sample records are synthetic UI data, not live monitoring or model predictions.", icon="ℹ️")
    critical = int((df.severity == "Critical").sum()) if not df.empty else 0
    high = int((df.severity == "High").sum()) if not df.empty else 0
    medium = int((df.severity == "Medium").sum()) if not df.empty else 0
    cols = st.columns(4)
    for col, args in zip(cols, [("Critical Threats",critical,"✹",COLORS["Critical"]),("High Threats",high,"▲",COLORS["High"]),("Medium Threats",medium,"⬟",COLORS["Medium"]),("Total Threats",len(df),"◉","#38a2ff")]):
        with col: metric(*args, foot="Recorded detections")
    st.write("")
    left,right=st.columns([1.25,1])
    with left:
        st.markdown('<div class="card"><div class="section-title">Threat Activity</div><div class="muted">Threat records by severity · sample activity</div>',unsafe_allow_html=True)
        series=demo_series(7).melt("Date",var_name="Severity",value_name="Threats")
        fig=px.line(series,x="Date",y="Threats",color="Severity",color_discrete_map=COLORS,markers=True)
        st.plotly_chart(chart_theme(fig,250),use_container_width=True,config={"displayModeBar":False})
        st.markdown('</div>',unsafe_allow_html=True)
    with right:
        st.markdown('<div class="card"><div class="section-title">System Status</div>',unsafe_allow_html=True)
        for name,state in [("Detection Service","Ready"),("SQLite Database","Connected"),("Model Integration","Configured" if load_model()[0] is not None else "Not connected")]:
            st.markdown(f'<div style="display:flex;justify-content:space-between;padding:11px 2px;border-bottom:1px solid #153650"><span>{name}</span><span class="muted"><span class="status-dot">●</span> &nbsp;{state}</span></div>',unsafe_allow_html=True)
        st.markdown('</div>',unsafe_allow_html=True)
        st.markdown('<div class="card"><div class="section-title">Recent Threats</div>',unsafe_allow_html=True)
        if df.empty: st.caption("No detections recorded yet.")
        else:
            show=df.head(5)[["threat","severity","source_ip","risk","status"]].rename(columns={"threat":"Threat","severity":"Severity","source_ip":"Source","risk":"Risk","status":"Status"})
            st.dataframe(show,hide_index=True,use_container_width=True,height=205)
        st.markdown('</div>',unsafe_allow_html=True)


def threat_analysis():
    df=get_detections()
    heading("Threat Analysis", "Review detected security threats and their evidence.")
    search,sev,status,period=st.columns([2,1.1,1.1,1])
    with search: query=st.text_input("Search threats",placeholder="Search threat, category, or source IP")
    with sev: severity=st.selectbox("Severity",["All Severities"]+SEVERITIES)
    with status: state=st.selectbox("Status",["All Statuses","Open","Investigating","Resolved"])
    with period: st.selectbox("Time range",["All time","Last 7 days","Last 30 days"])
    filtered=df.copy()
    if query: filtered=filtered[filtered.astype(str).apply(lambda c:c.str.contains(query,case=False,na=False)).any(axis=1)]
    if severity!="All Severities": filtered=filtered[filtered.severity==severity]
    if state!="All Statuses": filtered=filtered[filtered.status==state]
    st.caption(f"{len(filtered)} records · DEMO marks synthetic records; PREDICTION marks entries from the connected saved model.")
    if filtered.empty: st.info("No threats match the selected filters.")
    else:
        display=filtered[["id","threat","severity","category","risk","source_ip","status","detected_at","origin"]].copy()
        display["detected_at"]=pd.to_datetime(display.detected_at).dt.strftime("%Y-%m-%d %H:%M")
        display=display.rename(columns={"id":"ID","threat":"Threat","severity":"Severity","category":"Category","risk":"Risk","source_ip":"Source IP","status":"Status","detected_at":"Detected","origin":"Type"})
        st.dataframe(display,hide_index=True,use_container_width=True,height=350)
        ids=filtered.id.astype(int).tolist()
        selected=st.selectbox("Open threat detail",ids,format_func=lambda x: f"#{x} · {df.loc[df.id==x,'threat'].iloc[0]}")
        item=df[df.id==selected].iloc[0]
        with st.expander("Threat details",expanded=True):
            a,b,c,d=st.columns(4)
            with a: metric("Risk Score",f"{item.risk} / 100","◉","#fb6574")
            with b: metric("Status",item.status,"●","#ffb14d")
            with c: metric("Category",item.category,"⌕","#40a5ff")
            with d: metric("Detection Type",item.origin,"◇","#29d7aa")
            st.write(f"**Threat:** {item.threat} &nbsp; **Source:** `{item.source_ip}` &nbsp; **Detected:** {item.detected_at}")
            st.caption(item.details or "No additional evidence attached.")
            if item.origin=="PREDICTION": st.caption(f"Model confidence: {item.confidence:.1%}" if pd.notna(item.confidence) else "Model did not return a confidence score.")
            new_status=st.selectbox("Update status",["Open","Investigating","Resolved"],index=["Open","Investigating","Resolved"].index(item.status) if item.status in ["Open","Investigating","Resolved"] else 0,key=f"status_{selected}")
            if st.button("Save status",key=f"save_{selected}"):
                update_status(int(selected),new_status); st.success("Status updated."); st.rerun()


def new_detection():
    heading("New Detection", "Enter flow features for analysis using your saved Random Forest model.")
    model,message=load_model()
    st.markdown('<div class="card">',unsafe_allow_html=True)
    if model is None: st.warning(f"Model unavailable — {message} Detection entries can still be saved as manual records; no prediction will be fabricated.")
    else: st.success(f"Saved artifact ready. {message}")
    names=feature_names(model)
    st.caption(f"Input schema ({len(names)} fields): {', '.join(names)}")
    with st.form("detection_form"):
        cols=st.columns(3); values={}
        for i,name in enumerate(names):
            with cols[i%3]: values[name]=st.number_input(name,value=0.0,format="%.4f",key=f"feature_{i}")
        source=st.text_input("Source IP (optional)",placeholder="e.g. 192.168.1.10")
        submitted=st.form_submit_button("Analyze & Save",use_container_width=True)
    st.markdown('</div>',unsafe_allow_html=True)
    if submitted:
        if model is None:
            st.error("No model is connected. Configure the saved model path to run a prediction. No model prediction was generated.")
        else:
            try:
                result=predict(model,values)
                pred=result["category"]
                normal=pred.lower() in {"normal traffic","normal","benign"}
                sev="Low" if normal else "High"
                risk=8 if normal else 75
                if hasattr(model,"predict_proba") and result["confidence"] is not None: risk=8 if normal else round(35+60*result["confidence"])
                ip=source.strip() or "Not provided"
                save_detection("Normal Traffic" if normal else pred,sev,"Normal" if normal else pred,risk,ip,"PREDICTION",result["confidence"],f"Saved model output: {result['label']}")
                st.success("Prediction saved to SQLite.")
                st.markdown(f'<div class="card"><div class="section-title">Prediction Result</div><h2>{"Normal Traffic" if normal else pred}</h2><p>Risk score: <b>{risk}/100</b> · Severity: <b>{sev}</b> · Source: <b>{ip}</b></p><p>Confidence: <b>{result["confidence"]:.1%}</b></p></div>' if result["confidence"] is not None else f'<div class="card"><div class="section-title">Prediction Result</div><h2>{"Normal Traffic" if normal else pred}</h2><p>Risk score: <b>{risk}/100</b> · Severity: <b>{sev}</b></p><p>The model does not expose probability-based confidence.</p></div>',unsafe_allow_html=True)
            except Exception as exc: st.error(f"Prediction failed: {exc}")


def reports():
    heading("Detection Evaluation & Reports", "Model evaluation summaries and security reporting.")
    st.info("Evaluation metrics below are illustrative demonstration values from the design reference. Replace them with metrics calculated on your held-out test set; no model is retrained here.",icon="ℹ️")
    metrics=demo_metrics()
    cols=st.columns(4)
    for col,key in zip(cols,["Accuracy","Precision","Recall","F1 Score"]):
        with col: metric(key,f"{metrics[key]:.2f}%","◉","#43a5ff","Demonstration metric")
    left,right=st.columns([1.15,1])
    with left:
        st.markdown('<div class="card"><div class="section-title">Confusion Matrix</div><div class="muted">Illustrative evaluation summary</div>',unsafe_allow_html=True)
        mat=pd.DataFrame([[metrics["True Positive"],metrics["False Negative"]],[metrics["False Positive"],metrics["True Negative"]]],index=["Actual Threat","Actual Normal"],columns=["Predicted Threat","Predicted Normal"])
        st.dataframe(mat,use_container_width=True)
        st.markdown('</div>',unsafe_allow_html=True)
    with right:
        st.markdown('<div class="card"><div class="section-title">False Positives / False Negatives</div>',unsafe_allow_html=True)
        a,b=st.columns(2)
        with a: metric("False Positives",metrics["False Positive"],"✓","#23d6a0","Demo evaluation")
        with b: metric("False Negatives",metrics["False Negative"],"!","#ff5769","Demo evaluation")
        st.markdown('</div>',unsafe_allow_html=True)
    df=get_detections()
    a,b=st.columns(2)
    with a:
        st.markdown('<div class="card"><div class="section-title">Risk & Severity Summary</div>',unsafe_allow_html=True)
        if not df.empty:
            counts=df.severity.value_counts().reindex(SEVERITIES,fill_value=0).rename_axis("Severity").reset_index(name="Threats")
            fig=px.pie(counts,values="Threats",names="Severity",hole=.62,color="Severity",color_discrete_map=COLORS)
            st.plotly_chart(chart_theme(fig,260),use_container_width=True,config={"displayModeBar":False})
        st.markdown('</div>',unsafe_allow_html=True)
    with b:
        st.markdown('<div class="card"><div class="section-title">Top Threat Categories</div>',unsafe_allow_html=True)
        if not df.empty:
            cats=df.category.value_counts().head(6).rename_axis("Category").reset_index(name="Threats")
            fig=px.bar(cats,x="Threats",y="Category",orientation="h",color="Threats",color_continuous_scale=["#0e5aa3","#35a4ff"])
            fig.update_layout(coloraxis_showscale=False)
            st.plotly_chart(chart_theme(fig,260),use_container_width=True,config={"displayModeBar":False})
        st.markdown('</div>',unsafe_allow_html=True)
    csv=df.to_csv(index=False).encode("utf-8")
    st.download_button("Download detections CSV",csv,file_name=f"cybersheid-report-{datetime.now():%Y%m%d}.csv",mime="text/csv")
    report={"generated_at":datetime.now().isoformat(timespec="seconds"),"note":"Illustrative metrics are demonstration values; detections are tagged by origin.","metrics":metrics,"detections":df.to_dict(orient="records")}
    st.download_button("Download security report (JSON)",json.dumps(report,indent=2,default=str),file_name=f"cybersheid-report-{datetime.now():%Y%m%d}.json",mime="application/json")


def settings():
    heading("Alert & Resolution Analytics", "Monitor alert status and resolution progress.")
    df=get_detections()
    total=len(df); resolved=int((df.status=="Resolved").sum()) if total else 0; pending=total-resolved
    cols=st.columns(4)
    for col,args in zip(cols,[("Total Alerts",total,"✦","#9166ff"),("Resolved",resolved,"✓","#26d7a1"),("Pending",pending,"◉","#ffb432"),("Avg. Resolution Time","—","◷","#38a2ff")]):
        with col: metric(*args,foot="Recorded detections" if args[0]!="Avg. Resolution Time" else "Not available without resolution timestamps")
    st.write("")
    left,mid,right=st.columns([1,1,1.2])
    with left:
        st.markdown('<div class="card"><div class="section-title">Alert Status</div>',unsafe_allow_html=True)
        if total:
            counts=df.status.value_counts().rename_axis("Status").reset_index(name="Alerts")
            fig=px.pie(counts,values="Alerts",names="Status",hole=.6,color_discrete_sequence=["#25c99a","#f7bd33","#1687ee"])
            st.plotly_chart(chart_theme(fig,235),use_container_width=True,config={"displayModeBar":False})
        st.markdown('</div>',unsafe_allow_html=True)
    with mid:
        st.markdown('<div class="card"><div class="section-title">Alerts by Severity</div>',unsafe_allow_html=True)
        counts=df.severity.value_counts().reindex(SEVERITIES,fill_value=0).rename_axis("Severity").reset_index(name="Alerts")
        fig=px.bar(counts,x="Severity",y="Alerts",color="Severity",color_discrete_map=COLORS)
        st.plotly_chart(chart_theme(fig,235),use_container_width=True,config={"displayModeBar":False})
        st.markdown('</div>',unsafe_allow_html=True)
    with right:
        st.markdown('<div class="card"><div class="section-title">Alert records</div><div class="muted">Status updates are available in Threat Analysis.</div>',unsafe_allow_html=True)
        st.dataframe(df[["threat","severity","status","origin"]].head(6).rename(columns={"threat":"Threat","severity":"Severity","status":"Status","origin":"Type"}),hide_index=True,use_container_width=True,height=235)
        st.markdown('</div>',unsafe_allow_html=True)
    st.markdown('<div class="card"><div class="section-title">Application & Model Information</div>',unsafe_allow_html=True)
    model,message=load_model()
    st.write("**Application:** CYBERSHEID · Streamlit cybersecurity threat analysis")
    st.write(f"**Database:** SQLite · `{__import__('cybersheid.data',fromlist=['DB_PATH']).DB_PATH}`")
    st.write(f"**Saved model:** {'Connected' if model is not None else 'Not connected'} · {message}")
    st.caption("This application analyzes manually entered flow-feature values and stored records. It does not perform live network monitoring, packet capture, or automatic attack blocking.")
    st.markdown('</div>',unsafe_allow_html=True)


def run():
    inject_css()
    page=shell()
    {"Dashboard":dashboard,"Threat Analysis":threat_analysis,"New Detection":new_detection,"Reports":reports,"Settings":settings}[page]()
