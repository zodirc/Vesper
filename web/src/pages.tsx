import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Notice, useSession } from "./app";
import {
  assetFrom, dispositionFrom, endpointFrom, findingFrom, grantFrom, hypothesisFrom, observationFrom,
  packFrom, pointFrom, revisionFrom, rows, scanFrom, scheduleFrom, snapshotFrom, targetFrom, templateFrom, when, zeroID,
  type Asset, type Endpoint, type Finding, type Grant, type Hypothesis, type Observation, type ObservationPoint,
  type Pack, type Revision, type ScanRun, type Schedule, type Snapshot, type Target, type Template,
} from "./model";

const operations = [
  ["discovery", "主机发现"],
  ["connect", "连接"],
  ["protocol_probe", "协议探测"],
  ["config_check", "配置检查"],
  ["active_check", "主动检测"],
] as const;

const terminal = new Set(["completed", "completed_with_errors", "failed", "cancelled", "cancelling"]);

function localStamp(date = new Date()): string {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function OverviewPage() {
  const { client } = useSession();
  const [point, setPoint] = useState<ObservationPoint | null>(null);
  const [counts, setCounts] = useState({ grants: 0, scans: 0, findings: 0, open: 0 });
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    let live = true;
    async function load() {
      try {
        const [points, grants, scans, findings] = await Promise.all([
          client.request("GET", "/api/v1/observation-points"),
          client.request("GET", "/api/v1/grants"),
          client.request("GET", "/api/v1/scan-runs"),
          client.request("GET", "/api/v1/findings"),
        ]);
        if (!live) return;
        const pointRows = rows(points, "observation_points");
        const findingRows = rows(findings, "findings").map(findingFrom);
        setPoint(pointRows[0] ? pointFrom(pointRows[0]) : null);
        setCounts({
          grants: rows(grants, "grants").length,
          scans: rows(scans, "scan_runs").length,
          findings: findingRows.length,
          open: findingRows.filter((item) => item.status === "open" || item.status === "reopened").length,
        });
        setError(null);
      } catch (err) {
        if (live) setError(err);
      }
    }
    void load();
    return () => { live = false; };
  }, [client]);

  return (
    <>
      <h2>概览</h2>
      <Notice error={error} />
      <div className="grid">
        <div className="card"><span className="muted">授权</span><b>{counts.grants}</b></div>
        <div className="card"><span className="muted">扫描</span><b>{counts.scans}</b></div>
        <div className="card"><span className="muted">Finding</span><b>{counts.findings}</b></div>
        <div className="card"><span className="muted">未关闭</span><b>{counts.open}</b></div>
      </div>
      {point && (
        <section className="panel form">
          <h2>本机观察点</h2>
          <p>{point.platform} / {point.architecture} / {point.nodeType}</p>
          <p className="muted">标识 {point.id}</p>
          <p>网络接口</p>
          {point.interfaces.length === 0 ? <p>无</p> : <ul>{point.interfaces.map((item) => <li key={item}>{item}</li>)}</ul>}
          <p>能力</p>
          {point.capabilities.length === 0 ? <p>无</p> : <ul>{point.capabilities.map((item) => <li key={item}>{item}</li>)}</ul>}
          <p>权限</p>
          {point.privileges.length === 0 ? <p>无</p> : <ul>{point.privileges.map((item) => <li key={item}>{item}</li>)}</ul>}
          <p>主动检测隔离 {point.isolation || "未记录"}</p>
          <p>探针兼容</p>
          {point.compatibility.length === 0 ? <p>未记录</p> : <ul>{point.compatibility.map((item) => <li key={item}>{item}</li>)}</ul>}
        </section>
      )}
    </>
  );
}

export function GrantsPage() {
  const { client } = useSession();
  const [grants, setGrants] = useState<Grant[]>([]);
  const [points, setPoints] = useState<string[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [revisions, setRevisions] = useState<Revision[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [name, setName] = useState("");
  const [subject, setSubject] = useState("user");
  const [kind, setKind] = useState("ip");
  const [value, setValue] = useState("");
  const [transports, setTransports] = useState<string[]>(["tcp"]);
  const [portStart, setPortStart] = useState(1);
  const [portEnd, setPortEnd] = useState(1024);
  const [ops, setOps] = useState<string[]>(["discovery", "connect", "protocol_probe"]);
  const [validFrom, setValidFrom] = useState(localStamp());
  const [validUntil, setValidUntil] = useState("");
  const [reason, setReason] = useState("");
  const [maxTargets, setMaxTargets] = useState(32);
  const [maxAddresses, setMaxAddresses] = useState(256);
  const [maxConnections, setMaxConnections] = useState(200);
  const [maxRequests, setMaxRequests] = useState(200);
  const [maxConcurrency, setMaxConcurrency] = useState(8);
  const [maxRate, setMaxRate] = useState(50);
  const [maxRuntime, setMaxRuntime] = useState(300);
  const [maxEvidence, setMaxEvidence] = useState(8 << 20);

  async function load() {
    const [grantBody, pointBody] = await Promise.all([
      client.request("GET", "/api/v1/grants"),
      client.request("GET", "/api/v1/observation-points"),
    ]);
    setGrants(rows(grantBody, "grants").map(grantFrom));
    setPoints(rows(pointBody, "observation_points").map((row) => pointFrom(row).id).filter(Boolean));
  }

  useEffect(() => {
    void load().catch(setError);
  }, [client]);

  function toggle(list: string[], item: string, setList: (next: string[]) => void) {
    setList(list.includes(item) ? list.filter((entry) => entry !== item) : [...list, item]);
  }

  async function create(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      await client.request("POST", "/api/v1/grants", {
        name,
        subject_type: subject,
        target_selectors: [{ kind, value }],
        allowed_transports: transports,
        allowed_ports: [{ start: portStart, end: portEnd }],
        allowed_operations: ops,
        observation_point_ids: points,
        valid_from: new Date(validFrom).toISOString(),
        ...(validUntil ? { valid_until: new Date(validUntil).toISOString() } : {}),
        max_targets: maxTargets,
        max_addresses: maxAddresses,
        max_connections: maxConnections,
        max_requests: maxRequests,
        max_concurrency: maxConcurrency,
        max_rate_per_second: maxRate,
        max_runtime_seconds: maxRuntime,
        max_evidence_bytes: maxEvidence,
      });
      setName("");
      await load();
    } catch (err) {
      setError(err);
    }
  }

  async function approve(id: string) {
    setError(null);
    try {
      await client.request("POST", `/api/v1/grants/${id}/approve`, {});
      await load();
      if (selected === id) await open(id);
    } catch (err) {
      setError(err);
    }
  }

  async function revoke(id: string) {
    setError(null);
    try {
      await client.request("POST", `/api/v1/grants/${id}/revoke`, { reason });
      await load();
      if (selected === id) await open(id);
    } catch (err) {
      setError(err);
    }
  }

  async function open(id: string) {
    setSelected(id);
    const body = await client.request("GET", `/api/v1/grants/${id}/revisions`);
    setRevisions(rows(body, "revisions").map(revisionFrom));
  }

  return (
    <>
      <h2>授权</h2>
      <Notice error={error} />
      <form className="panel form" onSubmit={(event) => void create(event)}>
        <div className="row">
          <label>名称<input value={name} onChange={(event) => setName(event.target.value)} required /></label>
          <label>主体
            <select value={subject} onChange={(event) => setSubject(event.target.value)}>
              <option value="user">user</option>
              <option value="system">system</option>
              <option value="worker_group">worker_group</option>
            </select>
          </label>
          <label>选择器
            <select value={kind} onChange={(event) => setKind(event.target.value)}>
              <option value="ip">ip</option>
              <option value="cidr">cidr</option>
              <option value="hostname">hostname</option>
            </select>
          </label>
          <label>值<input value={value} onChange={(event) => setValue(event.target.value)} required /></label>
        </div>
        <div className="checks">
          {["tcp", "udp"].map((item) => (
            <label key={item}><input type="checkbox" checked={transports.includes(item)} onChange={() => toggle(transports, item, setTransports)} />{item}</label>
          ))}
        </div>
        <div className="checks">
          {operations.map(([item, label]) => (
            <label key={item}><input type="checkbox" checked={ops.includes(item)} onChange={() => toggle(ops, item, setOps)} />{label}</label>
          ))}
        </div>
        <div className="row">
          <label>起始端口<input type="number" min={1} max={65535} value={portStart} onChange={(event) => setPortStart(Number(event.target.value))} /></label>
          <label>结束端口<input type="number" min={1} max={65535} value={portEnd} onChange={(event) => setPortEnd(Number(event.target.value))} /></label>
          <label>生效<input type="datetime-local" value={validFrom} onChange={(event) => setValidFrom(event.target.value)} required /></label>
          <label>到期<input type="datetime-local" value={validUntil} onChange={(event) => setValidUntil(event.target.value)} /></label>
        </div>
        <p className="muted">观察点 {points.join(", ") || "尚未读取"}。下面的数字是这次草稿的执行上限，审批后才生效。</p>
        <div className="row">
          <label>目标数<input type="number" min={1} value={maxTargets} onChange={(event) => setMaxTargets(Number(event.target.value))} /></label>
          <label>地址数<input type="number" min={1} value={maxAddresses} onChange={(event) => setMaxAddresses(Number(event.target.value))} /></label>
          <label>连接数<input type="number" min={1} value={maxConnections} onChange={(event) => setMaxConnections(Number(event.target.value))} /></label>
          <label>请求数<input type="number" min={1} value={maxRequests} onChange={(event) => setMaxRequests(Number(event.target.value))} /></label>
          <label>并发<input type="number" min={1} value={maxConcurrency} onChange={(event) => setMaxConcurrency(Number(event.target.value))} /></label>
          <label>每秒速率<input type="number" min={1} value={maxRate} onChange={(event) => setMaxRate(Number(event.target.value))} /></label>
          <label>最长秒数<input type="number" min={1} value={maxRuntime} onChange={(event) => setMaxRuntime(Number(event.target.value))} /></label>
          <label>证据字节<input type="number" min={1} value={maxEvidence} onChange={(event) => setMaxEvidence(Number(event.target.value))} /></label>
        </div>
        <button className="primary" type="submit">创建草稿</button>
      </form>
      <table>
        <thead><tr><th>名称</th><th>状态</th><th>范围</th><th>操作</th><th></th></tr></thead>
        <tbody>
          {grants.map((grant) => (
            <tr key={grant.id}>
              <td>{grant.name}<div className="muted">{grant.subjectType}</div></td>
              <td><span className="status">{grant.status}</span></td>
              <td>{grant.selectors.map((item) => `${item.kind}:${item.value}`).join(", ")}<div className="muted">{grant.transports.join("/")} {grant.ports.map((item) => `${item.start}-${item.end}`).join(", ")}</div></td>
              <td>{grant.operations.join(", ")}</td>
              <td>
                <button type="button" onClick={() => void open(grant.id)}>审计</button>
                {grant.status === "draft" && <button type="button" onClick={() => void approve(grant.id)}>审批</button>}
                {grant.status !== "revoked" && <button className="danger" type="button" disabled={reason.trim() === ""} onClick={() => void revoke(grant.id)}>撤销</button>}
              </td>
            </tr>
          ))}
          {grants.length === 0 && <tr><td colSpan={5}>当前没有授权。</td></tr>}
        </tbody>
      </table>
      <label>撤销原因<input value={reason} onChange={(event) => setReason(event.target.value)} /></label>
      {selected && (
        <section>
          <h2>审计</h2>
          {(() => {
            const grant = grants.find((item) => item.id === selected);
            return grant ? <p className="muted">已保存上限：目标 {grant.maxTargets}，地址 {grant.maxAddresses}，连接 {grant.maxConnections}，请求 {grant.maxRequests}，并发 {grant.maxConcurrency}，每秒 {grant.maxRatePerSecond}，最长 {grant.maxRuntimeSeconds} 秒，证据 {grant.maxEvidenceBytes} 字节。生效 {when(grant.validFrom)}{grant.validUntil ? `，到期 ${when(grant.validUntil)}` : ""}。</p> : null;
          })()}
          <table>
            <thead><tr><th>动作</th><th>时间</th><th>操作者</th></tr></thead>
            <tbody>
              {revisions.map((item) => (
                <tr key={item.id}><td>{item.action}</td><td>{when(item.at)}</td><td>{item.actorId}</td></tr>
              ))}
              {revisions.length === 0 && <tr><td colSpan={3}>这条授权没有审计记录。</td></tr>}
            </tbody>
          </table>
        </section>
      )}
    </>
  );
}

export function ScansPage() {
  const { client } = useSession();
  const navigate = useNavigate();
  const { id } = useParams();
  const [runs, setRuns] = useState<ScanRun[]>([]);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [detail, setDetail] = useState<ScanRun | null>(null);
  const [observations, setObservations] = useState<Observation[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [type, setType] = useState("ip");
  const [transport, setTransport] = useState("tcp");
  const [ports, setPorts] = useState("");
  const [port, setPort] = useState("");
  const [grantID, setGrantID] = useState("");
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [scheduleName, setScheduleName] = useState("");
  const [scheduleTrigger, setScheduleTrigger] = useState("scheduled");
  const [scheduleInterval, setScheduleInterval] = useState("86400");
  const [scheduleTarget, setScheduleTarget] = useState("");
  const [scheduleType, setScheduleType] = useState("ip");
  const [scheduleTransport, setScheduleTransport] = useState("tcp");
  const [schedulePorts, setSchedulePorts] = useState("");
  const [schedulePort, setSchedulePort] = useState("");

  async function loadList() {
    const [scanBody, grantBody, scheduleBody] = await Promise.all([
      client.request("GET", "/api/v1/scan-runs"),
      client.request("GET", "/api/v1/grants"),
      client.request("GET", "/api/v1/scan-schedules"),
    ]);
    const nextRuns = rows(scanBody, "scan_runs").map(scanFrom);
    const nextGrants = rows(grantBody, "grants").map(grantFrom);
    setRuns(nextRuns);
    setSchedules(rows(scheduleBody, "scan_schedules").map(scheduleFrom));
    setGrants(nextGrants);
    if (!grantID) {
      const active = nextGrants.find((item) => item.status === "active");
      if (active) setGrantID(active.id);
    }
  }

  async function loadDetail(scanID: string) {
    const [runBody, observationBody] = await Promise.all([
      client.request("GET", `/api/v1/scan-runs/${scanID}`),
      client.request("GET", `/api/v1/scan-runs/${scanID}/observations`),
    ]);
    setDetail(scanFrom(runBody as Record<string, unknown>));
    setObservations(rows(observationBody, "observations").map(observationFrom));
  }

  useEffect(() => {
    let live = true;
    const tick = () => {
      loadList().catch((err) => { if (live) setError(err); });
    };
    tick();
    const timer = window.setInterval(tick, 2000);
    return () => { live = false; window.clearInterval(timer); };
  }, [client]);

  useEffect(() => {
    if (!id) {
      setDetail(null);
      return;
    }
    let live = true;
    const tick = () => {
      loadDetail(id).catch((err) => { if (live) setError(err); });
    };
    tick();
    const timer = window.setInterval(tick, 2000);
    return () => { live = false; window.clearInterval(timer); };
  }, [client, id]);

  async function create(event: FormEvent) {
    event.preventDefault();
    setError(null);
    const parsed = ports.split(/[^0-9]+/).filter(Boolean).map((item) => Number(item));
    try {
      const created = await client.request<{ id: string }>("POST", "/api/v1/scan-runs", {
        name,
        target,
        type,
        transport,
        ports: type === "endpoint" ? [] : parsed,
        ...(type === "endpoint" && port ? { port: Number(port) } : {}),
        grant_id: grantID,
      });
      setName("");
      await loadList();
      navigate(`/scans/${created.id}`);
    } catch (err) {
      setError(err);
    }
  }

  async function createSchedule(event: FormEvent) {
    event.preventDefault();
    setError(null);
    const parsed = schedulePorts.split(/[^0-9]+/).filter(Boolean).map((item) => Number(item));
    try {
      await client.request("POST", "/api/v1/scan-schedules", {
        name: scheduleName,
        trigger_type: scheduleTrigger,
        interval_seconds: Number(scheduleInterval),
        grant_id: grantID,
        ...(scheduleTrigger === "scheduled" ? {
          target: scheduleTarget,
          type: scheduleType,
          transport: scheduleTransport,
          ports: scheduleType === "endpoint" ? [] : parsed,
          ...(scheduleType === "endpoint" && schedulePort ? { port: Number(schedulePort) } : {}),
        } : {}),
      });
      setScheduleName("");
      await loadList();
    } catch (err) {
      setError(err);
    }
  }

  async function setSchedule(scheduleID: string, enabled: boolean) {
    setError(null);
    try {
      await client.request("POST", `/api/v1/scan-schedules/${scheduleID}/${enabled ? "enable" : "disable"}`);
      await loadList();
    } catch (err) {
      setError(err);
    }
  }

  async function cancel(scanID: string) {
    setError(null);
    try {
      await client.request("POST", `/api/v1/scan-runs/${scanID}/cancel`);
      await loadDetail(scanID);
      await loadList();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <>
      <h2>扫描</h2>
      <Notice error={error} />
      <form className="panel form" onSubmit={(event) => void create(event)}>
        <div className="row">
          <label>名称<input value={name} onChange={(event) => setName(event.target.value)} required /></label>
          <label>目标<input value={target} onChange={(event) => setTarget(event.target.value)} required /></label>
          <label>类型
            <select value={type} onChange={(event) => setType(event.target.value)}>
              <option value="ip">ip</option>
              <option value="cidr">cidr</option>
              <option value="hostname">hostname</option>
              <option value="endpoint">endpoint</option>
            </select>
          </label>
          <label>传输
            <select value={transport} onChange={(event) => setTransport(event.target.value)}>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
            </select>
          </label>
          {type === "endpoint"
            ? <label>端口<input value={port} onChange={(event) => setPort(event.target.value)} required /></label>
            : <label>端口<input value={ports} onChange={(event) => setPorts(event.target.value)} placeholder="80,443" required /></label>}
          <label>授权
            <select value={grantID} onChange={(event) => setGrantID(event.target.value)} required>
              <option value="">选择已生效授权</option>
              {grants.filter((item) => item.status === "active").map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
            </select>
          </label>
        </div>
        <button className="primary" type="submit">创建扫描</button>
      </form>
      <form className="panel form" onSubmit={(event) => void createSchedule(event)}>
        <h2>周期</h2>
        <div className="row">
          <label>名称<input value={scheduleName} onChange={(event) => setScheduleName(event.target.value)} required /></label>
          <label>触发
            <select value={scheduleTrigger} onChange={(event) => setScheduleTrigger(event.target.value)}>
              <option value="scheduled">scheduled</option>
              <option value="reassessment">reassessment</option>
            </select>
          </label>
          <label>间隔秒数<input type="number" min={1} value={scheduleInterval} onChange={(event) => setScheduleInterval(event.target.value)} required /></label>
          {scheduleTrigger === "scheduled" && (
            <>
              <label>目标<input value={scheduleTarget} onChange={(event) => setScheduleTarget(event.target.value)} required /></label>
              <label>类型
                <select value={scheduleType} onChange={(event) => setScheduleType(event.target.value)}>
                  <option value="ip">ip</option>
                  <option value="cidr">cidr</option>
                  <option value="hostname">hostname</option>
                  <option value="endpoint">endpoint</option>
                </select>
              </label>
              <label>传输
                <select value={scheduleTransport} onChange={(event) => setScheduleTransport(event.target.value)}>
                  <option value="tcp">tcp</option>
                  <option value="udp">udp</option>
                </select>
              </label>
              {scheduleType === "endpoint"
                ? <label>端口<input value={schedulePort} onChange={(event) => setSchedulePort(event.target.value)} required /></label>
                : <label>端口<input value={schedulePorts} onChange={(event) => setSchedulePorts(event.target.value)} placeholder="80,443" required /></label>}
            </>
          )}
          <label>授权
            <select value={grantID} onChange={(event) => setGrantID(event.target.value)} required>
              <option value="">选择已生效授权</option>
              {grants.filter((item) => item.status === "active").map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
            </select>
          </label>
        </div>
        <button className="primary" type="submit">登记周期</button>
      </form>
      <table>
        <thead><tr><th>名称</th><th>触发</th><th>状态</th><th>间隔</th><th>下次</th><th>结果</th><th></th></tr></thead>
        <tbody>
          {schedules.map((item) => (
            <tr key={item.id}>
              <td>{item.name}</td>
              <td>{item.trigger}</td>
              <td><span className="status">{item.status}</span></td>
              <td>{item.intervalSeconds}</td>
              <td>{when(item.nextRunAt)}</td>
              <td>{item.lastResult}</td>
              <td>
                {item.status === "enabled"
                  ? <button type="button" onClick={() => void setSchedule(item.id, false)}>停用</button>
                  : <button type="button" onClick={() => void setSchedule(item.id, true)}>启用</button>}
              </td>
            </tr>
          ))}
          {schedules.length === 0 && <tr><td colSpan={7}>当前没有周期。</td></tr>}
        </tbody>
      </table>
      <table>
        <thead><tr><th>名称</th><th>状态</th><th>触发</th><th>进度</th><th>创建</th></tr></thead>
        <tbody>
          {runs.map((run) => (
            <tr key={run.id}>
              <td><Link to={`/scans/${run.id}`}>{run.name || run.id}</Link></td>
              <td><span className="status">{run.status}</span></td>
              <td>{run.trigger}</td>
              <td>{run.done}/{run.total}，失败 {run.failed}，跳过 {run.skipped}</td>
              <td>{when(run.createdAt)}</td>
            </tr>
          ))}
          {runs.length === 0 && <tr><td colSpan={5}>当前没有扫描。</td></tr>}
        </tbody>
      </table>
      {detail && (
        <section className="panel form">
          <h2>{detail.name || detail.id}</h2>
          <p><span className="status">{detail.status}</span> {detail.summary}</p>
          <p className="muted">开始 {when(detail.startedAt)}，结束 {when(detail.finishedAt)}</p>
          {!terminal.has(detail.status) && <button className="danger" type="button" onClick={() => void cancel(detail.id)}>取消</button>}
          <table>
            <thead><tr><th>类型</th><th>主体</th><th>结果</th><th>时间</th><th>值</th></tr></thead>
            <tbody>
              {observations.map((item) => (
                <tr key={item.id}>
                  <td>{item.type}</td>
                  <td>{item.subject}</td>
                  <td>{item.status}</td>
                  <td>{when(item.observedAt)}</td>
                  <td><details><summary>查看</summary><pre>{JSON.stringify(item.value, null, 2)}</pre></details></td>
                </tr>
              ))}
              {observations.length === 0 && <tr><td colSpan={5}>这次运行还没有观察。</td></tr>}
            </tbody>
          </table>
        </section>
      )}
    </>
  );
}

export function AssetsPage() {
  const { client } = useSession();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    void Promise.all([
      client.request("GET", "/api/v1/assets"),
      client.request("GET", "/api/v1/endpoints"),
      client.request("GET", "/api/v1/targets"),
    ]).then(([assetBody, endpointBody, targetBody]) => {
      setAssets(rows(assetBody, "assets").map(assetFrom));
      setEndpoints(rows(endpointBody, "endpoints").map(endpointFrom));
      setTargets(rows(targetBody, "targets").map(targetFrom));
    }).catch(setError);
  }, [client]);

  return (
    <>
      <h2>资产</h2>
      <Notice error={error} />
      <h2>主机</h2>
      <table>
        <thead><tr><th>平台</th><th>版本</th><th>标识摘要</th><th>状态</th><th>最近观察</th></tr></thead>
        <tbody>
          {assets.map((item) => (
            <tr key={item.id}><td>{item.family} {item.name}</td><td>{item.version}</td><td>{item.hash}</td><td>{item.status}</td><td>{when(item.lastSeen)}</td></tr>
          ))}
          {assets.length === 0 && <tr><td colSpan={5}>还没有由机器标识建立的资产。</td></tr>}
        </tbody>
      </table>
      <h2>端点</h2>
      <table>
        <thead><tr><th>地址</th><th>传输</th><th>端口</th><th>状态</th><th>资产</th></tr></thead>
        <tbody>
          {endpoints.map((item) => (
            <tr key={item.id}><td>{item.address}</td><td>{item.transport}</td><td>{item.port}</td><td>{item.state}</td><td>{zeroID(item.assetId) ? "" : item.assetId}</td></tr>
          ))}
          {endpoints.length === 0 && <tr><td colSpan={5}>还没有端点。</td></tr>}
        </tbody>
      </table>
      <h2>扫描目标</h2>
      <table>
        <thead><tr><th>类型</th><th>输入</th><th>规范值</th><th>传输</th><th>创建</th></tr></thead>
        <tbody>
          {targets.map((item) => (
            <tr key={item.id}><td>{item.type}</td><td>{item.raw}</td><td>{item.normalized}</td><td>{item.transport}</td><td>{when(item.createdAt)}</td></tr>
          ))}
          {targets.length === 0 && <tr><td colSpan={5}>还没有扫描目标。</td></tr>}
        </tbody>
      </table>
    </>
  );
}

export function ServicesPage() {
  const { client } = useSession();
  const [items, setItems] = useState<Hypothesis[]>([]);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    void client.request("GET", "/api/v1/hypotheses").then((body) => {
      setItems(rows(body, "hypotheses").map(hypothesisFrom));
    }).catch(setError);
  }, [client]);
  return (
    <>
      <h2>服务</h2>
      <Notice error={error} />
      <table>
        <thead><tr><th>类型</th><th>产品</th><th>版本</th><th>规范版本</th><th>状态</th><th>置信度</th><th>端点</th></tr></thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <td>{item.service}</td><td>{item.product}</td><td>{item.version}</td><td>{item.normalized}</td>
              <td>{item.status}</td><td>{item.confidence}</td><td>{zeroID(item.endpointId) ? "" : item.endpointId}</td>
            </tr>
          ))}
          {items.length === 0 && <tr><td colSpan={7}>还没有服务候选。识别只解释已经采集的观察。</td></tr>}
        </tbody>
      </table>
    </>
  );
}

export function FindingsPage() {
  const { client } = useSession();
  const { id } = useParams();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [dispositions, setDispositions] = useState<ReturnType<typeof dispositionFrom>[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [text, setText] = useState("");
  const [kind, setKind] = useState("accept_risk");
  const [reason, setReason] = useState("");
  const [detection, setDetection] = useState("");
  const [grantID, setGrantID] = useState("");

  async function load() {
    const [findingBody, grantBody] = await Promise.all([
      client.request("GET", "/api/v1/findings"),
      client.request("GET", "/api/v1/grants"),
    ]);
    setFindings(rows(findingBody, "findings").map(findingFrom).sort((a, b) => b.lastSeen.localeCompare(a.lastSeen)));
    const nextGrants = rows(grantBody, "grants").map(grantFrom);
    setGrants(nextGrants);
    if (!grantID) {
      const active = nextGrants.find((item) => item.status === "active");
      if (active) setGrantID(active.id);
    }
    if (id) {
      const body = await client.request("GET", `/api/v1/findings/${id}/dispositions`);
      setDispositions(rows(body, "dispositions").map(dispositionFrom));
    }
  }

  useEffect(() => { void load().catch(setError); }, [client, id]);

  const current = findings.find((item) => item.id === id);

  async function dispose(event: FormEvent) {
    event.preventDefault();
    if (!id) return;
    setError(null);
    setText("");
    try {
      await client.request("POST", `/api/v1/findings/${id}/dispositions`, {
        disposition_type: kind,
        reason,
        ...(detection ? { detection_id: detection } : {}),
      });
      setReason("");
      setText("处置已追加。");
      await load();
    } catch (err) {
      setError(err);
    }
  }

  async function verify(event: FormEvent) {
    event.preventDefault();
    if (!id) return;
    setError(null);
    setText("");
    try {
      const created = await client.request<{ id: string }>("POST", `/api/v1/findings/${id}/verification`, { grant_id: grantID });
      setText(`复核扫描已创建：${created.id}`);
    } catch (err) {
      setError(err);
    }
  }

  return (
    <>
      <h2>风险</h2>
      <Notice error={error} text={text} />
      <table>
        <thead><tr><th>标题</th><th>漏洞</th><th>严重性</th><th>状态</th><th>类型</th><th>最近出现</th></tr></thead>
        <tbody>
          {findings.map((item) => (
            <tr key={item.id}>
              <td><Link to={`/findings/${item.id}`}>{item.title || item.key}</Link></td>
              <td>{item.vulnerabilityId}</td>
              <td>{item.severity}</td>
              <td><span className="status">{item.dispositionType ? `${item.status} · ${item.dispositionType}` : item.status}</span></td>
              <td>{item.type}</td>
              <td>{when(item.lastSeen)}</td>
            </tr>
          ))}
          {findings.length === 0 && <tr><td colSpan={6}>当前没有 Finding。</td></tr>}
        </tbody>
      </table>
      {current && (
        <section className="panel form">
          <h2>{current.title || current.vulnerabilityId}</h2>
          <p>状态 {current.dispositionType ? `${current.status} · ${current.dispositionType}` : current.status}，严重性 {current.severity}，类型 {current.type}</p>
          <p className="muted">资产 {zeroID(current.assetId) ? "无" : current.assetId}，端点 {zeroID(current.endpointId) ? "无" : current.endpointId}</p>
          <form onSubmit={(event) => void dispose(event)} className="form">
            <div className="row">
              <label>处置
                <select value={kind} onChange={(event) => setKind(event.target.value)}>
                  <option value="accept_risk">accept_risk</option>
                  <option value="exception">exception</option>
                  <option value="suppress">suppress</option>
                  <option value="false_positive">false_positive</option>
                  <option value="reopen">reopen</option>
                  <option value="resolve">resolve</option>
                </select>
              </label>
              <label>原因<input value={reason} onChange={(event) => setReason(event.target.value)} required /></label>
              <label>检测标识<input value={detection} onChange={(event) => setDetection(event.target.value)} placeholder="resolve 需要" /></label>
            </div>
            <button type="submit">追加处置</button>
          </form>
          <form onSubmit={(event) => void verify(event)} className="row">
            <label>复核授权
              <select value={grantID} onChange={(event) => setGrantID(event.target.value)}>
                {grants.filter((item) => item.status === "active").map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
              </select>
            </label>
            <button type="submit">创建复核扫描</button>
          </form>
          <table>
            <thead><tr><th>类型</th><th>原因</th><th>时间</th><th>到期</th></tr></thead>
            <tbody>
              {dispositions.map((item) => (
                <tr key={item.id}><td>{item.type}</td><td>{item.reason}</td><td>{when(item.createdAt)}</td><td>{when(item.validUntil)}</td></tr>
              ))}
              {dispositions.length === 0 && <tr><td colSpan={4}>还没有处置。</td></tr>}
            </tbody>
          </table>
        </section>
      )}
    </>
  );
}

export function LibraryPage() {
  const { client } = useSession();
  const [fingerprints, setFingerprints] = useState<Pack[]>([]);
  const [configs, setConfigs] = useState<Pack[]>([]);
  const [templates, setTemplates] = useState<Template[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [text, setText] = useState("");

  async function load() {
    const [fingerBody, configBody, templateBody] = await Promise.all([
      client.request("GET", "/api/v1/fingerprint-packs"),
      client.request("GET", "/api/v1/config-packs"),
      client.request("GET", "/api/v1/active-templates"),
    ]);
    setFingerprints(rows(fingerBody, "packs").map(packFrom));
    setConfigs(rows(configBody, "packs").map(packFrom));
    setTemplates(rows(templateBody, "templates").map(templateFrom));
  }

  useEffect(() => { void load().catch(setError); }, [client]);

  async function upload(path: string, body: unknown) {
    setError(null);
    setText("");
    try {
      await client.request("POST", path, body);
      setText("已导入。新扫描才会使用随后发布并启用的内容。");
      await load();
    } catch (err) {
      setError(err);
    }
  }

  async function act(path: string) {
    setError(null);
    try {
      await client.request("POST", path);
      await load();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <>
      <h2>规则与模板</h2>
      <Notice error={error} text={text} />
      <FileForm label="Nmap 服务探针" accept=".txt,.probe" onText={(document) => void upload("/api/v1/fingerprint-packs", { format: "nmap-service-probes", document })} />
      <PackTable packs={fingerprints} kind="fingerprint" onAct={(id, action) => void act(`/api/v1/fingerprint-packs/${id}/${action}`)} />
      <FileForm label="配置规则" accept=".yaml,.yml" onText={(document) => void upload("/api/v1/config-packs", { format: "vesper-config", document })} />
      <PackTable packs={configs} kind="config" onAct={(id, action) => void act(`/api/v1/config-packs/${id}/${action}`)} />
      <FileForm label="Nuclei HTTP 模板" accept=".yaml,.yml" onText={(template) => void upload("/api/v1/active-templates", { template })} />
      <table>
        <thead><tr><th>名称</th><th>键</th><th>严重性</th><th>状态</th><th>启用</th><th>请求上限</th><th></th></tr></thead>
        <tbody>
          {templates.map((item) => (
            <tr key={item.id}>
              <td>{item.name}</td><td>{item.key}</td><td>{item.severity}</td><td>{item.status}</td><td>{item.enabled ? "是" : "否"}</td><td>{item.bound}</td>
              <td>
                <button type="button" onClick={() => void act(`/api/v1/active-templates/${item.id}/publish`)}>发布</button>
                <button type="button" onClick={() => void act(`/api/v1/active-templates/${item.id}/disable`)}>停用</button>
              </td>
            </tr>
          ))}
          {templates.length === 0 && <tr><td colSpan={7}>没有调用方提交的主动检测模板。</td></tr>}
        </tbody>
      </table>
    </>
  );
}

function PackTable({ packs, kind, onAct }: { packs: Pack[]; kind: string; onAct: (id: string, action: "publish" | "deprecate") => void }) {
  return (
    <table>
      <thead><tr><th>版本</th><th>状态</th><th>{kind === "fingerprint" ? "接受 / 跳过" : "规则数"}</th><th>许可记录</th><th></th></tr></thead>
      <tbody>
        {packs.map((item) => (
          <tr key={item.id}>
            <td>{item.version}</td>
            <td><span className="status">{item.status}</span></td>
            <td>{kind === "fingerprint" ? `${item.accepted ?? 0} / ${item.skipped ?? 0}` : item.rules ?? ""}</td>
            <td>{item.license ? "已记录" : "无"}</td>
            <td>
              <button type="button" onClick={() => onAct(item.id, "publish")}>发布</button>
              <button type="button" onClick={() => onAct(item.id, "deprecate")}>弃用</button>
            </td>
          </tr>
        ))}
        {packs.length === 0 && <tr><td colSpan={5}>没有可列出的包。</td></tr>}
      </tbody>
    </table>
  );
}

function FileForm({ label, accept, onText }: { label: string; accept: string; onText: (text: string) => void }) {
  return (
    <form className="row" onSubmit={(event) => {
      event.preventDefault();
      const input = event.currentTarget.elements.namedItem("file");
      const file = input instanceof HTMLInputElement ? input.files?.[0] : undefined;
      if (!file) return;
      void file.text().then(onText);
    }}>
      <label>{label}<input name="file" type="file" accept={accept} required /></label>
      <button type="submit">导入</button>
    </form>
  );
}

export function IntelPage() {
  const { client } = useSession();
  const [snapshots, setSnapshots] = useState<Snapshot[]>([]);
  const [source, setSource] = useState("nvd");
  const [error, setError] = useState<unknown>(null);
  const [text, setText] = useState("");

  async function load() {
    const body = await client.request("GET", "/api/v1/intel/snapshots");
    setSnapshots(rows(body, "snapshots").map(snapshotFrom));
  }

  useEffect(() => { void load().catch(setError); }, [client]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const input = event.currentTarget.elements.namedItem("file");
    const file = input instanceof HTMLInputElement ? input.files?.[0] : undefined;
    if (!file) return;
    setError(null);
    setText("");
    try {
      const raw = (await file.text()).trim();
      const document = raw.startsWith("{") || raw.startsWith("[") ? JSON.parse(raw) as unknown : raw;
      const created = await client.request<{ id: string }>("POST", "/api/v1/intel/imports", { source, document });
      setText(`快照 ${created.id} 已发布。`);
      await load();
    } catch (err) {
      setError(err);
    }
  }

  async function syncFeed(source: string) {
    setError(null);
    setText("");
    try {
      const result = await client.request<{ last_result: string; statement_count: number }>("POST", `/api/v1/intel/feeds/${source}/sync`);
      setText(`${source} 同步结果是 ${result.last_result}，当前快照有 ${result.statement_count} 条语句。`);
      await load();
    } catch (err) {
      setError(err);
    }
  }

  async function reassess(id: string) {
    setError(null);
    setText("");
    try {
      const result = await client.request<{ detections: number }>("POST", `/api/v1/intel/snapshots/${id}/reassess`);
      setText(`重新评估追加了 ${result.detections} 条检测。这次不创建补充采集。`);
    } catch (err) {
      setError(err);
    }
  }

  return (
    <>
      <h2>情报</h2>
      <Notice error={error} text={text} />
      <form className="row" onSubmit={(event) => void submit(event)}>
        <label>来源
          <select value={source} onChange={(event) => setSource(event.target.value)}>
            <option value="nvd">nvd</option>
            <option value="osv">osv</option>
            <option value="kev">kev</option>
            <option value="epss">epss</option>
            <option value="vendor_advisory">vendor_advisory</option>
            <option value="distro_advisory">distro_advisory</option>
          </select>
        </label>
        <label>文档<input name="file" type="file" accept=".json" required /></label>
        <button type="submit">导入</button>
      </form>
      <div className="row">
        <button type="button" onClick={() => void syncFeed("nvd")}>同步 NVD 下一页</button>
        <button type="button" onClick={() => void syncFeed("kev")}>同步 KEV</button>
        <button type="button" onClick={() => void syncFeed("epss")}>同步 EPSS</button>
      </div>
      <table>
        <thead><tr><th>来源</th><th>语句</th><th>摘要</th><th>发布时间</th><th></th></tr></thead>
        <tbody>
          {snapshots.map((item) => (
            <tr key={item.id}>
              <td>{item.sources.join(", ")}</td>
              <td>{item.statements}</td>
              <td>{item.digest.slice(0, 16)}</td>
              <td>{when(item.publishedAt)}</td>
              <td><button type="button" onClick={() => void reassess(item.id)}>重新评估</button></td>
            </tr>
          ))}
          {snapshots.length === 0 && <tr><td colSpan={5}>还没有情报快照。</td></tr>}
        </tbody>
      </table>
    </>
  );
}
