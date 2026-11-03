# 动态服务暴露面与漏洞识别系统

本仓库当前实现单机扫描闭环中的这些部分：

- 授权校验。环回、链路本地和 `169.254.169.254` 只有在选择器完全落在受保护地址空间内时才允许连接。
- 本地预算账本。有效上限取各层预算中更严格的值。
- TCP Connect 扫描。同一地址上的并发连接数取授权里的 `max_concurrency`。超时记为 `no_response`，连接拒绝记为 `closed`。
- HTTP、TLS、SSH 有界探测。端口号不直接决定服务身份。协议观察记录探针版本、实际连接地址、传输协议、请求轮次、响应字节数和证据摘要。
- UDP 探针框架。没有协议请求时结果保持 `unknown`。
- 已发布指纹规则和配置规则。指纹规则只读取协议观察，端口号不产生产品。同一端点出现多种服务候选时，每条候选记为 `conflict`，并把支持其他服务的观察写入 `contradicting_observation_ids`。配置规则在采集事实缺失时给出证据不足，不把缺失当成通过，同时记录命中和未满足的条件。主动检测在网络隔离未被证明时返回 `unsupported`，当前没有主动检测执行器。评估运行的 `result_summary` 统计该次评估实际产生的候选数量和检测状态数量。
- 服务候选和通用生态版本适用性判断。`deb`、`rpm` 因缺少对应版本比较器返回证据不足。NVD、OSV、CISA KEV 和 EPSS 文档可以导入。导入先校验来源、结构和分数，通过后写入情报语句；内容变化时保留旧语句并发布新的情报快照。扫描运行创建时冻结当时的快照。重新评估只读取指定快照，追加新的评估结果，不改写已有观察和已有检测结果。存在配置或平台约束时，版本落入区间也记为证据不足。
- Finding 与 FindingOccurrence 分离。相同漏洞标识在不同端点上保持不同 Finding。Finding 的 `last_occurrence_id` 指向最近一次发生记录。漏洞 Finding 记录受影响产品，配置 Finding 记录规则标识。配置检测结果保存规则标识、规则版本和规则自身的严重性。漏洞适用性使用独立的 `vulnerability` 评估，配置判断使用 `config` 评估，服务识别使用 `service_identification` 评估。确认的漏洞检测结果引用已校验证据。授权的创建、审批和撤销各写一条修订，并保存当时的授权内容。
- 本机 Linux 采集：操作系统、接口和监听套接字。进程、服务、软件包和防火墙返回 `unsupported`。采集状态写入观察值的 `collection_status`。观察的 `result_status` 只使用 `observed`、`no_response`、`unreachable`、`not_scanned`、`unsupported`、`error`、`partial`。观察的 `source_identity` 是产生该事实的本地 Worker。主机采集在识别到机器标识后写入 `asset_id`。
- 证据文件按临时文件、摘要、同步和原子改名发布。存储后端是 `local_fs`，存储键是相对对象键。协议响应在摘要校验后记为 `verified`。HTTP 和 SSH 的类型是 `raw_response`，TLS 证书的类型是 `tls_certificate`。内容编码是 `identity`，因为文件保存的是未压缩原始字节。HTTP 响应的内容类型是 `application/http`，TLS 证书是 `application/pkix-cert`，SSH 标识行是 `text/plain`。设计要求证据带有敏感级，但没有规定协议响应属于哪一级，因此这些内容记为 `internal`。确认的漏洞发生记录只引用已校验证据。本机观察点记录当前架构，并在保存节点状态时更新最近在线时间。

控制服务入口是 `cmd/vesperd`。HTTP 请求只创建任务和读取结果，扫描单元由独立循环领取。启动前需要设置 `VESPER_ADMIN_USER`、`VESPER_ADMIN_PASSWORD` 和 `VESPER_DATABASE_URL`。服务启动时按文件名顺序执行 `migrations` 目录中的 SQL。默认监听 `127.0.0.1:8077`。

每次新的 TCP 连接前都会续期当前租约，并把这次续期写入对应 StageAttempt 的 `heartbeat_at`。租约或 fencing token 已经失效时不再拨号。取消后的运行同样不再拨号。尝试结束时，`resource_usage` 记录该尝试相对预算账本的连接数、请求数、证据字节数和耗时，`result_digest` 是该尝试观察内容的摘要。没有观察时不写 `result_digest`。ScanUnit 的 `result_summary` 记录该尝试的观察数量和状态分布。

创建扫描时先提交 `planning` 运行和计划输入。触发类型记为 `manual`。`effective_budget` 保存创建时的授权预算上限，不随后续消耗变化。当前没有单独的任务预算策略，因此快照就是授权上限。域名解析成功后写入 `dns_resolution` 观察，来源种类是 `network`，并把通过授权的地址写入该运行的计划快照。域名解析被取消或超时时运行保持 `planning`，下一次领取会重新解析并再次校验。已经判定的计划失败会把该运行标为 `failed`。Go 标准库解析器不返回 TTL，也不返回逐跳 CNAME 链，因此观察只记录实际拿到的地址、记录类型和最终规范名，不补写 TTL。领取、租约、fencing token 和结果提交在同一个数据库事务中锁定 `scope_grant`、`scan_run` 和 `scan_unit` 后更新。观察幂等键包含 `scan_run_id`、`scan_unit_id`、`stage_key`、观察类型、主体和内容摘要，不以 `attempt_id` 作为唯一键。取消之后不再创建协议探测单元。授权不再有效的排队单元会被跳过，运行根据现有汇总规则结束。

预算计数在扫描单元开始和结束时写入数据库。单元执行过程中进程退出时，该次尚未提交的连接计数不会记入上限。预算耗尽不会重试。短暂的证据存储失败会在尝试次数上限内重试。

版本适用性结果的 `executor_type` 写为 `applicability`。设计列出的执行器是 `nuclei`、`native_probe`、`config_engine` 和 `fingerprint_engine`，版本区间判断不属于这四类，因此没有改名充数。配置规则命中时使用规则自己的 `severity`。漏洞 Finding 的 `severity` 只使用情报语句上已经规范化的等级。来源没有给出 `info`、`low`、`medium`、`high` 或 `critical` 时保持空字符串。CVSS `NONE` 不改写成 `info`。KEV 和 EPSS 只随来源语句保存，不参与是否受影响的判断，也不换算成风险分。

## 尚未接入的设计要求

管理界面、远程 Worker、远程 Agent 和 Nuclei 执行器尚未实现。情报导入读取调用方提交的 NVD 2.0、OSV、CISA KEV 或 EPSS 文档，不从外部网络拉取，也没有厂商公告和发行版公告适配器。重新评估不创建补充采集任务，设计没有给出证据过期时限，新的扫描仍要单独授权。主机发现目前只使用 TCP Connect，ARP 和 ICMP 没有实现。非 ASCII 域名会在登记时拒绝，IDNA 转换尚未实现。UDP 探针不发送报文。`deb` 和 `rpm` 没有版本比较器，结果保持证据不足。两个控制进程同时写同一数据库时，Finding 等非任务聚合仍可能互相覆盖。设计列出了 ScanUnit 级预算，但没有给出单阶段的数量上限，因此执行端只执行授权上的运行级预算和探针自身的超时、字节数限制，没有另设一套单元配额。`scheduled`、`reassessment` 和 `verification` 三种触发类型尚未实现，当前创建路径只写 `manual`。
