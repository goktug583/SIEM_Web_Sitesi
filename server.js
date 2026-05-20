require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const https = require('https');

const app = express();
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json());
app.use(express.static('public')); 

const axiosInstance = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false })
});


app.get('/health', async (req, res) => {
    const health = {
        backend: "ok",
        wazuhApi: "checking",
        indexer: "checking",
        timestamp: new Date().toISOString()
    };

    try {
        const token = await getWazuhToken();
        health.wazuhApi = token ? "connected" : "failed";
    } catch (error) {
        health.wazuhApi = "failed";
    }

    try {
        const indexerResponse = await axiosInstance.get(
            `${process.env.WAZUH_INDEXER_URL}`,
            {
                auth: {
                    username: process.env.WAZUH_INDEXER_USER,
                    password: process.env.WAZUH_INDEXER_PASSWORD
                },
                timeout: 5000
            }
        );

        health.indexer = indexerResponse.status === 200 ? "connected" : "failed";
    } catch (error) {
        health.indexer = "failed";
    }

    const isHealthy =
        health.backend === "ok" &&
        health.wazuhApi === "connected" &&
        health.indexer === "connected";

    res.status(isHealthy ? 200 : 503).json(health);
});




// Wazuh API Token Alıcı
async function getWazuhToken() {
    try {
        const response = await axiosInstance.get(`${process.env.WAZUH_API_URL}/security/user/authenticate`, {
            auth: { username: process.env.WAZUH_USER, password: process.env.WAZUH_PASSWORD }
        });
        return response.data.data.token;
    } catch (error) { return null; }
}

// 1. GERÇEK SOC HİBRİT İZLEME: DONANIM + GÜVENLİK METRİKLERİ
// 1. GERÇEK SOC HİBRİT İZLEME: DONANIM + GÜVENLİK METRİKLERİ (DİSK EKLENDİ - KUSURSUZ SÜRÜM)
app.get('/api/donanim', async (req, res) => {
    const token = await getWazuhToken();
    if (!token) return res.status(500).json({ hata: "Token alınamadı!" });

    try {
        const agentsResponse = await axiosInstance.get(`${process.env.WAZUH_API_URL}/agents`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const agents = agentsResponse.data.data.affected_items;

        const result = await Promise.all(
            agents.map(async (agent) => {
                // İŞTE DEĞİŞKENLERİN OLMASI GEREKEN YER BURASI (GLOBAL SCOPE)
                let criticalCount = 0;
                let failedLoginCount = 0;
                let liveCpu = "Veri Yok";
                let liveRam = "Veri Yok";
                let liveDisk = "Veri Yok"; 

                if (agent.status === 'active') {
                    try {
                        // A) SON 24 SAATİN GÜVENLİK İSTATİSTİKLERİ
                        const statQuery = {
                            query: { 
                                bool: { 
                                    must: [
                                        { range: { timestamp: { gte: "now-24h" } } },
                                        { match: { "agent.id": agent.id } }
                                    ]
                                }
                            },
                            aggs: {
                                kritikler: { filter: { range: { "rule.level": { gte: 4 } } } },
                                basarisiz_loginler: { filter: { match: { "rule.groups": "authentication_failed" } } }
                            },
                            size: 0 
                        };
                        const statRes = await axiosInstance.post(`${process.env.WAZUH_INDEXER_URL}/wazuh-alerts-*/_search`, statQuery, {
                            auth: { username: process.env.WAZUH_INDEXER_USER, password: process.env.WAZUH_INDEXER_PASSWORD }
                        });
                        
                        criticalCount = statRes.data.aggregations.kritikler.doc_count;
                        failedLoginCount = statRes.data.aggregations.basarisiz_loginler.doc_count;

                        // B) CANLI NABIZ LOGLARINI ÇEKME (KURAL ID: 100013)
                        const liveQuery = {
                            query: { 
                                bool: { 
                                    must: [
                                        { match: { "rule.id": "100013" } },
                                        { match: { "agent.id": agent.id } }
                                    ]
                                }
                            },
                            sort: [{ timestamp: { order: "desc" } }],
                            size: 20
                        };
                        const liveRes = await axiosInstance.post(`${process.env.WAZUH_INDEXER_URL}/wazuh-alerts-*/_search`, liveQuery, {
                            auth: { username: process.env.WAZUH_INDEXER_USER, password: process.env.WAZUH_INDEXER_PASSWORD }
                        });

                        // CPU, RAM VE DİSK YÜZDELERİNİ ÇEKME
                        liveRes.data.hits.hits.forEach(hit => {
                            const out = hit._source.full_log || "";
                            if (out.includes("live_cpu_usage") && liveCpu === "Veri Yok") {
                                const parts = out.split(':');
                                liveCpu = "%" + parts[parts.length - 1].trim().replace('%', ''); 
                            }
                            if (out.includes("live_ram_usage") && liveRam === "Veri Yok") {
                                const parts = out.split(':');
                                liveRam = "%" + parts[parts.length - 1].trim().replace('%', ''); 
                            }
                            if (out.includes("live_disk_usage") && liveDisk === "Veri Yok") {
                                const parts = out.split(':');
                                liveDisk = "%" + parts[parts.length - 1].trim().replace('%', ''); 
                            }
                        });

                    } catch (err) { console.log(`Agent ${agent.id} verileri çekilemedi.`); }
                }

                // ZAMAN VE BAĞLANTI DURUMU HESAPLAMA
                const lastKeeep = new Date(agent.lastKeepAlive);
                const now = new Date();
                const diffSeconds = Math.floor((now - lastKeeep) / 1000);
                let streamStatus = diffSeconds < 300 ? "AKTİF" : "UYARI";
                if (agent.status !== "active") streamStatus = "KOPUK";

                // WAZUH SERVER IP'SİNİ DÜZELTME
                let gercekIp = agent.ip || "IP Yok";
                if (agent.id === "000") gercekIp = "100.102.65.62";

                // SONUÇLARI FRONTEND'E GÖNDERME
                return {
                    id: agent.id,
                    name: agent.name,
                    ip: gercekIp,
                    status: agent.status,
                    os: agent.os?.name || agent.os?.platform || "Bilinmiyor",
                    lastKeepAlive: agent.lastKeepAlive || "Bilinmiyor",
                    streamStatus: streamStatus,
                    liveCpu: liveCpu,
                    liveRam: liveRam,
                    liveDisk: liveDisk, // EKSİK OLAN SATIR BURADAYDI!
                    criticalCount: criticalCount,
                    failedLoginCount: failedLoginCount
                };
            })
        );
        res.json(result);
    } catch (error) {
    console.error("Ajan verileri çekilemedi:", error.message);

    res.status(503).json({
        hata: "Ajan verileri geçici olarak alınamadı.",
        kaynak: "Wazuh API / Indexer",
        durum: "telemetry_unavailable",
        zaman: new Date().toISOString()
    });
}
});

// ============================================================================
// ============================================================================
// ============================================================================
// 1. KİMLİK VE IP İZLEME (SAF HAM GİRİŞLER: WINDOWS + LINUX FAILED + LINUX SUCCESS)
// ============================================================================
// 1. KİMLİK VE IP İZLEME (SAF HAM GİRİŞLER: WINDOWS + LINUX FAILED + LINUX SUCCESS)
// ============================================================================
app.get('/api/kimlik-loglari', async (req, res) => {
    const token = await getWazuhToken();
    if (!token) return res.status(500).json({ hata: "Token alınamadı!" });

    try {
        const authOptions = {
            auth: {
                username: process.env.WAZUH_INDEXER_USER,
                password: process.env.WAZUH_INDEXER_PASSWORD
            }
        };

        // === 1. WINDOWS BASE SORGUSU ===
        const windowsBaseQuery = {
            query: {
                bool: {
                    must: [
                        { range: { timestamp: { gte: "now-7d" } } },
                        { match_phrase: { "data.win.system.providerName": "Microsoft-Windows-Security-Auditing" } },
                        { terms: { "data.win.system.eventID": ["4624", "4625"] } },
                        { terms: { "data.win.eventdata.logonType": ["2", "3", "10"] } }
                    ],
                    must_not: [
                        { term: { "data.win.eventdata.logonType": "5" } }, 
                        { wildcard: { "data.win.system.providerName": "*SQL*" } },
                        { wildcard: { "data.win.eventdata.targetUserName": "*MSSQL*" } },
                        { wildcard: { "data.win.eventdata.targetUserName": "*SQLTELEMETRY*" } },
                        { wildcard: { "data.win.eventdata.targetUserName": "*SQLEXPRESS*" } }
                    ]
                }
            },
            sort: [{ timestamp: { order: "desc" } }],
            size: 50
        };

        // === 2. LINUX BAŞARISIZ CONSOLE SORGUSU (Sadece 2501) ===
        const linuxFailedQuery = {
            query: {
                bool: {
                    must: [
                        { range: { timestamp: { gte: "now-7d" } } },
                        { match_phrase: { "agent.name": "sporthink-linux" } },
                        { term: { "rule.id": "2501" } }
                    ]
                }
            },
            sort: [{ timestamp: { order: "desc" } }],
            size: 25
        };

        // === 3. LINUX BAŞARILI CONSOLE SORGUSU ===
const linuxSuccessQuery = {
    query: {
        bool: {
            must: [
                { match_phrase: { "agent.name": "sporthink-linux" } },
                { range: { timestamp: { gte: "now-7d" } } }
            ],
            should: [
                { match_phrase: { "rule.id": "5501" } },
                { match_phrase: { "rule.id": "100006" } }
            ],
            minimum_should_match: 1
        }
    },
    sort: [{ timestamp: { order: "desc" } }],
    size: 25
};

        const [windowsResponse, linuxFailedResponse, linuxSuccessResponse] = await Promise.all([
            axiosInstance.post(`${process.env.WAZUH_INDEXER_URL}/wazuh-alerts-*/_search`, windowsBaseQuery, authOptions),
            axiosInstance.post(`${process.env.WAZUH_INDEXER_URL}/wazuh-alerts-*/_search`, linuxFailedQuery, authOptions),
            axiosInstance.post(`${process.env.WAZUH_INDEXER_URL}/wazuh-alerts-*/_search`, linuxSuccessQuery, authOptions)
        ]);

        const rawWindowsLogs = windowsResponse.data.hits.hits || [];
        const rawLinuxFailedLogs = linuxFailedResponse.data.hits.hits || [];
        const rawLinuxSuccessLogs = linuxSuccessResponse.data.hits.hits || [];
        
        

        const combinedRawLogs = [...rawWindowsLogs, ...rawLinuxFailedLogs, ...rawLinuxSuccessLogs];

        // === 4. MAPPING ===
        const mappedLogs = combinedRawLogs.map(hit => {
            const src = hit._source || {};
            const agentName = src.agent?.name || "N/A";
            
            let ruleId = String(src.rule?.id || "N/A");
            let eventId = String(src.data?.win?.system?.eventID || src.data?.win?.system?.eventId || src.data?.win?.system?.EventID || "N/A");

            let username = "N/A";
            let sourceIp = "N/A";
            let loginType = "N/A";
            let status = "Başarılı";

            // WINDOWS MAPPING
            if (eventId === "4624" || eventId === "4625") {
                username = src.data?.win?.eventdata?.targetUserName || src.data?.win?.eventdata?.TargetUserName || "N/A";
                sourceIp = src.data?.win?.eventdata?.ipAddress || src.data?.win?.eventdata?.IpAddress || "N/A";
                
                if (eventId === "4624") {
                    loginType = "Windows Logon";
                    status = "Başarılı";
                } else if (eventId === "4625") {
                    loginType = "Failed Windows Logon";
                    status = "Başarısız";
                }
            } 
            // LINUX LOCAL CONSOLE MAPPING
            else {
                username = src.data?.dstuser || "N/A";
                
                if (username === "N/A" && src.full_log) {
                    const forMatch = src.full_log.match(/FOR\s+'([^']+)'/i);
                    if (forMatch && forMatch[1]) {
                        username = forMatch[1];
                    } else {
                        const userMatch = src.full_log.match(/user=([^\s,]+)/i);
                        if (userMatch && userMatch[1]) {
                            username = userMatch[1];
                        }
                    }
                }
                
                if (username === "N/A") {
                    username = src.data?.srcuser || "N/A";
                }

                sourceIp = src.data?.srcip || "N/A";
                
                if (ruleId === "2501") {
                    loginType = "Failed Linux Console Login";
                    status = "Başarısız";
                } else if (ruleId === "5501" || ruleId === "100006") {
    loginType = ruleId === "100006"
        ? "Linux Console Login"
        : "Linux Console Login";
    status = "Başarılı";

                }
            }

            if (!sourceIp || sourceIp === "-" || sourceIp === "N/A" || sourceIp === "") {
                sourceIp = src.agent?.ip || "N/A";
            }


             // Windows sistem servis hesaplarını ve arka plan oturumlarını gizle
            if (
             username.startsWith("DWM-") ||
             username.startsWith("UMFD-") ||
             username.endsWith("$")
            ) {
             return null;
                    }




            return {
                _rawId: src.id || null,
                timestamp: src.timestamp || src["@timestamp"] || "N/A",
                targetHost: agentName,
                username: username,
                sourceIp: sourceIp,
                loginType: loginType,
                status: status,
                eventId: eventId,
                ruleId: ruleId
            };
        });

        // 1. TUZAK: MAPPING SONRASI
        

        const filteredLogs = mappedLogs.filter(log => log && log.loginType !== "N/A");

        // 2. TUZAK: FILTER SONRASI
        

        // === 5. AKILLI SLIDING WINDOW DEDUPLICATION ===
        const finalLogs = [];

        filteredLogs.forEach(log => {
            const logTime = log.timestamp !== "N/A" ? new Date(log.timestamp).getTime() : 0;

            if (log.eventId === "4624" || log.eventId === "4625") {
                const isDuplicate = finalLogs.some(existingLog => {
                    if (
                        existingLog.eventId === log.eventId &&
                        existingLog.targetHost === log.targetHost &&
                        existingLog.username === log.username &&
                        existingLog.sourceIp === log.sourceIp
                    ) {
                        const existingTime = existingLog.timestamp !== "N/A" ? new Date(existingLog.timestamp).getTime() : 0;
                        return Math.abs(logTime - existingTime) <= 2000;
                    }
                    return false;
                });

                if (!isDuplicate) {
                    delete log._rawId;
                    finalLogs.push(log);
                }
            } else {
                const isDuplicate = finalLogs.some(existingLog => existingLog._rawId === log._rawId && log._rawId !== null);
                if (!isDuplicate) {
                    delete log._rawId;
                    finalLogs.push(log);
                }
            }
        });

        // 3. TUZAK: DEDUP SONRASI (FİNAL)
        

        // === 6. KRONOLOJİK SIRALAMA ===
        finalLogs.sort((a, b) => {
            const timeA = a.timestamp !== "N/A" ? new Date(a.timestamp).getTime() : 0;
            const timeB = b.timestamp !== "N/A" ? new Date(b.timestamp).getTime() : 0;
            return timeB - timeA;
        });

        res.json(finalLogs.slice(0, 50));

    } catch (error) {
        console.error("Kimlik logları çekilirken hata:", error);
        res.status(500).json({ hata: "Loglar çekilemedi." });
    }
});

// 2. KUSURSUZ LOGIN YAKALAYICI (Tespit Edilemedi Rezaletine Son)
app.get('/api/loglar/basarisiz-login', async (req, res) => {
    try {
        const query = {
            query: { match: { "rule.groups": "authentication_failed" } },
            sort: [{ timestamp: { order: "desc" } }], size: 5
        };
        const response = await axiosInstance.post(`${process.env.WAZUH_INDEXER_URL}/wazuh-alerts-*/_search`, query, {
            auth: { username: process.env.WAZUH_INDEXER_USER, password: process.env.WAZUH_INDEXER_PASSWORD }
        });


        
        const loglar = response.data.hits.hits.map(hit => {
            const data = hit._source.data || {};
            const fullLog = hit._source.full_log || "";
            
            // Kullanıcıyı her delikten arıyoruz
            let denenen_hesap = data.win?.eventdata?.TargetUserName || data.win?.eventdata?.targetUserName || data.dstuser || data.user || data.srcuser || data.audit?.user?.name;
            
            // Eğer hala bulamadıysa, ham logun içindeki "user=root" veya "invalid user admin" kısımlarını makasla kesiyoruz
            if (!denenen_hesap) {
                const userMatch = fullLog.match(/user[= ]([a-zA-Z0-9_\-]+)/i) || fullLog.match(/for (?:invalid user )?([a-zA-Z0-9_\-]+)/i);
                if (userMatch) denenen_hesap = userMatch[1];
                else denenen_hesap = "Bilinmiyor";
            }
            if (denenen_hesap.includes("$")) denenen_hesap = "Sistem Servisi";

            let gercek_ip = data.srcip || data.win?.eventdata?.IpAddress || data.win?.eventdata?.ipAddress;
            if (!gercek_ip || gercek_ip === "-" || gercek_ip === "::1") gercek_ip = "127.0.0.1 (Lokal)";

            return { tarih: hit._source.timestamp, kaynak_ip: gercek_ip, denenen_hesap: denenen_hesap };
        });
        
        const temizLoglar = loglar.filter(l => l.denenen_hesap !== "Sistem Servisi");
        res.json(temizLoglar);
    } catch (error) { res.status(500).json({ hata: "Veritabanı hatası!" }); }
});

// 3. USER ACTIVITY / AI ANALİZİ: USE-CASE ALARMLARI
app.get('/api/loglar/kullanici-aktiviteleri', async (req, res) => {
    try {
        const query = {
            query: {
                bool: {
                    must: [
                        { range: { timestamp: { gte: "now-7d" } } },
                        {
                            terms: {
                                "rule.id": [
                                    "100002", "100003", "100004", "100005",
                                    "100006", "100007", "100008", "100009",
                                    "100010", "100011", "100012",
                                    "100014", "100015", "100016",
                                    "100017", "100019", "100020", "100021", "100022"
                                ]
                            }
                        }
                    ],
                    must_not: [
                        { term: { "rule.id": "100013" } },
                        { term: { "rule.id": "100018" } }
                    ]
                }
            },
            sort: [{ timestamp: { order: "desc" } }],
            size: 50
        };

        const response = await axiosInstance.post(
            `${process.env.WAZUH_INDEXER_URL}/wazuh-alerts-*/_search`,
            query,
            {
                auth: {
                    username: process.env.WAZUH_INDEXER_USER,
                    password: process.env.WAZUH_INDEXER_PASSWORD
                }
            }
        );

        const loglar = response.data.hits.hits.map(hit => {
            const source = hit._source || {};
            const data = source.data || {};
            const winEvent = data.win?.eventdata || {};
            const sqlAuditText = winEvent.data || "";
            const ruleId = String(source.rule?.id || "N/A");
            const ruleDesc = source.rule?.description || "Kural açıklaması yok";
            const fullLog = source.full_log || "";
            const agentName = source.agent?.name || "Bilinmiyor";

            const srcIp =
                data.srcip ||
                winEvent.IpAddress ||
                winEvent.ipAddress ||
                source.agent?.ip ||
                "127.0.0.1 (Lokal)";

            let user =
                data.dstuser ||
                data.srcuser ||
                data.user ||
                source.user ||
                data.mssql?.user ||
                data.sql?.user ||
                winEvent.SubjectUserName ||
                winEvent.subjectUserName ||
                winEvent.TargetUserName ||
                winEvent.targetUserName ||
                data.audit?.user?.name ||
                (sqlAuditText.match(/session_server_principal_name:([^\s]+)/i)?.[1]) ||
                (sqlAuditText.match(/server_principal_name:([^\s]+)/i)?.[1]) ||
                "Bilinmiyor";

            let command =
                data.audit?.command ||
                winEvent.CommandLine ||
                winEvent.commandLine ||
                winEvent.NewProcessName ||
                winEvent.newProcessName ||
                winEvent.Statement ||
                winEvent.statement ||
                data.statement ||
                data.Statement ||
                data.sql?.statement ||
                data.mssql?.statement ||
                (sqlAuditText.match(/statement:([^:]+?)(?=\s+additional_information:|\s+application_name:|$)/i)?.[1]?.trim()) ||
                "";

            if (!command && fullLog) {
                if (fullLog.includes("COMMAND=")) {
                    const cmdMatch = fullLog.match(/COMMAND=([^\n]+)/);
                    if (cmdMatch && cmdMatch[1]) {
                        command = cmdMatch[1]
                            .replace(/\/usr\/bin\//g, "")
                            .replace(/\/bin\//g, "")
                            .trim();
                    }
                } else {
                    const regexMatch = fullLog.match(
                        /(DROP\s+TABLE\s+[a-zA-Z0-9_\.\[\]]+|EXEC\s+sp_configure[^;\n]*|CREATE\s+TABLE\s+[a-zA-Z0-9_\.\[\]]+|ALTER\s+TABLE\s+[a-zA-Z0-9_\.\[\]]+|SELECT[^;\n]*|whoami|net user|ipconfig \/all|powershell -enc|vssadmin\.exe|wevtutil\.exe|whoami\.exe|ipconfig\.exe|net\.exe|net1\.exe|cat \/etc\/shadow|nano \/etc\/ssh\/sshd_config|sudo su|\/etc\/shadow|\/etc\/ssh\/sshd_config)/i
                    );
                    if (regexMatch) command = regexMatch[0].trim();
                }
            }

            if (ruleId === "100012" && command === "DROP TABLE") {
                const dropMatch =
                    sqlAuditText.match(/statement:(DROP\s+TABLE\s+[a-zA-Z0-9_\.\[\]]+)/i) ||
                    fullLog.match(/DROP\s+TABLE\s+[a-zA-Z0-9_\.\[\]]+/i);

                if (dropMatch) command = dropMatch[1] || dropMatch[0];
            }

            if (ruleId === "100007") {
                command = `EXEC sp_configure ${sqlAuditText || winEvent.data || "SQL Server config değişikliği"}`;
                if (user === "Bilinmiyor") {
                    user = "SQL Server Servisi";
                }
            }

            if (!command) {
                if (["100004", "100006", "100017", "100019", "100020", "100021", "100022"].includes(ruleId)) {
                    command = "Kullanıcı / sistem davranışı analiz edildi";
                } else {
                    command = "Komut Yok (Sistem/Korelasyon Olayı)";
                }
            }

            let olayTipi = "Genel Güvenlik Olayı";

            if (ruleId === "100002") olayTipi = "Windows Yetki / Hesap Değişikliği";
            else if (ruleId === "100003") olayTipi = "Linux Hassas Dosya Erişimi";
            else if (ruleId === "100004") olayTipi = "Şüpheli/Farklı IP Girişi";
            else if (ruleId === "100005") olayTipi = "Ransomware Şüphesi";
            else if (ruleId === "100006") olayTipi = "Brute Force + Başarılı Giriş";
            else if (ruleId === "100007") olayTipi = "SQL Server Konfigürasyon Değişikliği";
            else if (ruleId === "100008") olayTipi = "Windows Keşif Komutu";
            else if (ruleId === "100009") olayTipi = "Linux Yetki Yükseltme";
            else if (ruleId === "100010") olayTipi = "Güvenlik/Log Servisi Durdurma";
            else if (ruleId === "100011") olayTipi = "SSH Konfigürasyon Müdahalesi";
            else if (ruleId === "100012") olayTipi = "MSSQL Kritik SQL İşlemi";
            else if (ruleId === "100014") olayTipi = "Windows Security Log Temizleme";
            else if (ruleId === "100015") olayTipi = "Zamanlanmış Görev Oluşturma";
            else if (ruleId === "100016") olayTipi = "Audit Politikası Değişikliği";
            else if (ruleId === "100017") olayTipi = "Windows Oturum Kapatma";
            else if (ruleId === "100019") olayTipi = "Çoklu Dosya Silme";
            else if (ruleId === "100020") olayTipi = "MSSQL Başarılı Giriş";
            else if (ruleId === "100021") olayTipi = "MSSQL Başarısız Giriş";
            else if (ruleId === "100022") olayTipi = "MSSQL Trigger Değişikliği";


            // Görünürlük standardizasyonu: "Bilinmiyor" ifadelerini SOC diline çevir
if (!user || user === "Bilinmiyor" || user === "N/A") {
    if (["100020", "100021", "100022", "100012", "100007"].includes(ruleId)) {
        user = "MSSQL Oturum Kullanıcısı";
    } else if (["100010", "100014", "100016"].includes(ruleId)) {
        user = "Sistem Servisi";
    } else if (["100004", "100006", "100019"].includes(ruleId)) {
        user = "Korelasyon Kuralı";
    } else {
        user = "Tanımlı Sistem Kullanıcısı";
    }
}

if (!command || command === "Komut Yok (Sistem/Korelasyon Olayı)") {
    if (ruleId === "100019") command = "Birden fazla dosya silme davranışı";
    else if (ruleId === "100020") command = "MSSQL başarılı oturum açma";
    else if (ruleId === "100021") command = "MSSQL başarısız oturum açma";
    else if (ruleId === "100022") command = "MSSQL trigger değişikliği";
    else if (ruleId === "100017") command = "Windows oturum kapatma";
    else if (ruleId === "100010") command = "Güvenlik/log servisi durdurma";
}

            const aiAnalizi =
                `Bu olay '${agentName}' sunucusunda tespit edildi. ` +
                `'${srcIp}' kaynak adresi üzerinden '${user}' kullanıcısı ile ilişkili bir işlem görüldü. ` +
                `Olay tipi: ${olayTipi}. SOC yorumu: ${ruleDesc}`;

            return {
                zaman: source.timestamp || "N/A",
                hedef_sunucu: agentName,
                kaynak_ip: srcIp,
                kullanici: user,
                calistirilan_komut: command,
                olay_tipi: olayTipi,
                kural_id: ruleId,
                kural_aciklamasi: ruleDesc,
                ai_cevirisi: aiAnalizi
            };
        });


// 100004 false positive temizliği:
// Windows makine hesapları, local loopback ve DWM/UMFD sistem oturumları şüpheli IP girişi olarak gösterilmez.
// FALSE POSITIVE TEMİZLİĞİ
const temizlenmisLoglar = loglar.filter(log => {
    if (!log) return false;

    const user = String(log.kullanici || "").trim();
    const ip = String(log.kaynak_ip || "").trim();

    // Windows sistem hesaplarını tamamen gizle
    if (
        user.startsWith("DWM-") ||
        user.startsWith("UMFD-") ||
        user.endsWith("$")
    ) {
        return false;
    }

    // Şüpheli giriş use-case'i için ek filtre
    if (log.kural_id === "100004") {

        // localhost girişleri
        if (
            ip === "127.0.0.1" ||
            ip === "::1" ||
            ip === "127.0.0.1 (Lokal)"
        ) {
            return false;
        }

        // makine hesabı
        if (user.endsWith("$")) {
            return false;
        }
    }

    return true;
});


        const benzersizLoglar = [];
        const gorulenler = new Set();

        temizlenmisLoglar.forEach(log => {
            let temizKomut = String(log.calistirilan_komut || "")
                .replace(/net1\.exe/gi, "net.exe");

            const zamanDakika = String(log.zaman || "").slice(0, 16);

            const anahtar = [
                zamanDakika,
                log.hedef_sunucu,
                log.kullanici,
                log.kural_id,
                temizKomut
            ].join("|");

            if (!gorulenler.has(anahtar)) {
                gorulenler.add(anahtar);
                log.calistirilan_komut = temizKomut;
                benzersizLoglar.push(log);
            }
        });

        res.json(benzersizLoglar);

    } catch (error) {
        console.error("Kullanıcı aktiviteleri çekilirken hata:", error.message);
        res.status(500).json({ hata: "Kullanıcı aktiviteleri çekilemedi." });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[BAŞARILI] Akıllı SIEM Backend Sunucusu çalışıyor! http://localhost:${PORT}`);
});