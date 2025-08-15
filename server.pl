#!/usr/bin/env perl
use strict;
use warnings;
use Mojolicious::Lite -signatures;
use DBI;
use Redis;
use JSON::MaybeXS qw(encode_json decode_json);
use Time::HiRes qw(gettimeofday);
use POSIX qw(strftime);

# =========================
# Config
# =========================
my $config = {
  cluster_key => $ENV{ECOBAT_CLUSTER_KEY} // 's3cr3t-clust3r-k3y',
  db_dsn      => $ENV{ECOBAT_DSN}      // 'dbi:Pg:dbname=ecobat;host=localhost',
  db_user     => $ENV{ECOBAT_DBUSER}   // 'ecobat',
  db_pass     => $ENV{ECOBAT_DBPASS}   // 'db-p@ssw0rd',
  redis_srv   => $ENV{ECOBAT_REDIS}    // '127.0.0.1:6379',
};

# =========================
# Conexões
# =========================
app->log->info("Connecting Postgres: $config->{db_dsn} ($config->{db_user})");
my $dbh = DBI->connect($config->{db_dsn}, $config->{db_user}, $config->{db_pass},
  { RaiseError => 1, AutoCommit => 1, pg_enable_utf8 => 1 })
  or die "DB error: $DBI::errstr";

app->log->info("Connecting Redis: $config->{redis_srv}");
my $redis = Redis->new(server => $config->{redis_srv}) or die "Redis error";



my %PROTO_MAP = ( TCP => 6, UDP => 17, ICMP => 1 );
sub norm_proto {
  my ($p) = @_;
  return 0 unless defined $p;
  return $p if $p =~ /^\d+$/;     # já numérico (1/6/17)
  $p = uc($p // '');
  return $PROTO_MAP{$p} // 0;     # texto -> número
}
# =========================
# Schema (idempotente)
# =========================
sub ensure_schema {
  $dbh->do(q{
    CREATE TABLE IF NOT EXISTS nodes (
      node_id   TEXT PRIMARY KEY,
      hostname  TEXT,
      status    TEXT,
      last_seen TIMESTAMPTZ DEFAULT NOW()
    )
  });
  $dbh->do(q{
    CREATE TABLE IF NOT EXISTS packets (
      id BIGSERIAL PRIMARY KEY,
      node_id   TEXT,
      "timestamp" TIMESTAMPTZ NOT NULL,
      src_ip    TEXT,
      dst_ip    TEXT,
      protocol  TEXT,
      length    INTEGER
    )
  });
  $dbh->do(q{ CREATE INDEX IF NOT EXISTS idx_packets_time ON packets("timestamp") });
  $dbh->do(q{ CREATE INDEX IF NOT EXISTS idx_packets_src  ON packets(src_ip) });

  $dbh->do(q{
    CREATE TABLE IF NOT EXISTS alerts (
      id BIGSERIAL PRIMARY KEY,
      "timestamp" TIMESTAMPTZ DEFAULT NOW(),
      node_id     TEXT,
      type        TEXT,
      severity    TEXT,
      src_ip      TEXT,
      dst_ip      TEXT,
      description TEXT
    )
  });
  $dbh->do(q{ CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts("timestamp") });

  $dbh->do(q{
    CREATE TABLE IF NOT EXISTS anomalous_ips (
      ip TEXT PRIMARY KEY
    )
  });
}
ensure_schema();

# =========================
# Helpers
# =========================
helper json_ok => sub ($c, $payload={}) { $c->render(json => { ok=>\1, %$payload }); };
helper now     => sub { strftime("%Y-%m-%dT%H:%M:%S", gmtime(time)) . "Z" };

sub _ok_key ($key) { defined $key && $key eq $config->{cluster_key} }


get '/' => sub {
    my $c = shift;
    $c->redirect_to('/dashboard');
};


# =========================
# API (ingestão)
# =========================
post '/api/register' => sub ($c) {
  my $p = $c->req->json // {};
  return $c->render(status=>400, json=>{ok=>\0, error=>'invalid json'}) unless ref $p eq 'HASH';
  return $c->render(status=>403, json=>{ok=>\0, error=>'forbidden'}) unless ($p->{key}//'') eq $config->{cluster_key};

  my $node = $p->{node_id} // 'unknown';
  my $host = $p->{host}    // 'unknown';

  eval {
    $dbh->do(q{
      INSERT INTO nodes (node_id, hostname, status, last_seen)
      VALUES (?, ?, 'online', NOW())
      ON CONFLICT (node_id)
      DO UPDATE SET hostname=EXCLUDED.hostname, status='online', last_seen=NOW()
    }, {}, $node, $host);

    $redis->hset('node_status', $node, time) if $redis;
    $redis->publish('nodes', encode_json({ node_id=>$node, hostname=>$host, status=>'online', last_seen=>time })) if $redis;
    1;
  } or do {
    my $err = $@ || 'unknown';
    app->log->error("register error: $err");
    return $c->render(status=>500, json=>{ok=>\0, error=>"register: $err"});
  };

  return $c->render(json=>{ok=>\1, registered=>$node});
};



post '/api/heartbeat' => sub ($c) {
  my $p = $c->req->json // {};
  return $c->render(status=>400, json=>{ok=>\0, error=>'invalid json'}) unless ref $p eq 'HASH';
  return $c->render(status=>403, json=>{ok=>\0, error=>'forbidden'}) unless ($p->{key}//'') eq $config->{cluster_key};

  my $node = $p->{node_id} // 'unknown';

  eval {
    $dbh->do(q{
      INSERT INTO nodes (node_id, hostname, status, last_seen)
      VALUES (?, 'unknown', 'online', NOW())
      ON CONFLICT (node_id)
      DO UPDATE SET status='online', last_seen=NOW()
    }, {}, $node);

    $redis->hset('node_status', $node, time) if $redis;
    $redis->publish('nodes', encode_json({ node_id=>$node, status=>'online', last_seen=>time })) if $redis;
    1;
  } or do {
    my $err = $@ || 'unknown';
    app->log->error("heartbeat error: $err");
    return $c->render(status=>500, json=>{ok=>\0, error=>"heartbeat: $err"});
  };

  return $c->render(json=>{ok=>\1, heartbeat=>$node});
};



post '/api/packets' => sub ($c) {
  my $p = $c->req->json // {};
  return $c->render(status=>400, json=>{ok=>\0, error=>'invalid json'}) unless ref $p eq 'HASH';
  return $c->render(status=>403, json=>{ok=>\0, error=>'forbidden'}) unless ($p->{key}//'') eq $config->{cluster_key};

  my $node    = $p->{node_id}  // 'unknown';
  my $packets = $p->{packets}  // [];
  return $c->render(status=>400, json=>{ok=>\0, error=>'packets must be array'}) unless ref $packets eq 'ARRAY';

  my $ing = 0;
  eval {
    my $sth = $dbh->prepare(q{
      INSERT INTO packets (node_id, "timestamp", src_ip, dst_ip, protocol, length)
      VALUES (?, COALESCE(?, NOW()), ?, ?, ?, ?)
    });

    for my $pkt (@$packets) {
      next unless ref $pkt eq 'HASH';
      $sth->execute(
        $node,
        $pkt->{"timestamp"},
        $pkt->{src_ip} // undef,
        $pkt->{dst_ip} // undef,
        norm_proto($pkt->{protocol}),          # 1/6/17
        int($pkt->{length}//0)
      );
      $ing++;
    }

    if (my ($big) = grep { ($_->{length}//0) > 1000 } @$packets) {
      $dbh->do(q{
        INSERT INTO alerts ("timestamp", node_id, type, severity, src_ip, dst_ip, description)
        VALUES (NOW(), ?, 'large_packet', 'low', ?, ?, 'Packet larger than 1000 bytes')
      }, {}, $node, $big->{src_ip}, $big->{dst_ip});
      $redis->publish('alerts', encode_json({ type=>'large_packet', node_id=>$node })) if $redis;
    }

    $redis->publish('packets', 0+@$packets) if $redis;
    1;
  } or do {
    my $err = $@ || 'unknown';
    app->log->error("packets error: $err");
    return $c->render(status=>500, json=>{ok=>\0, error=>"packets: $err"});
  };

  return $c->render(json=>{ok=>\1, ingested=>$ing});
};


# =========================
# API (dados p/ dashboard)
# =========================
get '/alerts_table' => sub ($c) {
  my $rows = $dbh->selectall_arrayref(q{
    SELECT type, severity, COUNT(*) as count
    FROM alerts
    WHERE timestamp > NOW() - INTERVAL '24 hours'
    GROUP BY type, severity
    ORDER BY count DESC
  }, { Slice=>{} });
  $c->render(json => { alerts => $rows });
};

get '/nodes_table' => sub ($c) {
  my $rows = $dbh->selectall_arrayref(q{
    SELECT node_id, hostname, status, last_seen
    FROM nodes
    ORDER BY last_seen DESC
  }, { Slice=>{} });
  $c->render(json => { nodes => $rows });
};

get '/talkers_table' => sub ($c) {
  my $rows = $dbh->selectall_arrayref(q{
    SELECT src_ip, COUNT(*) as packet_count
    FROM packets
    WHERE timestamp > NOW() - INTERVAL '1 hour'
    GROUP BY src_ip
    ORDER BY packet_count DESC
    LIMIT 10
  }, { Slice=>{} });
  $c->render(json => { talkers => $rows });
};

# =========================
# SSE de tempo real
# =========================
get '/updates' => sub ($c) {
  $c->inactivity_timeout(300);
  $c->res->headers->content_type('text/event-stream');
  $c->res->headers->cache_control('no-cache');
  $c->write("retry: 3000\n\n");

  my $send = sub ($channel, $message) {
    $c->write("event: $channel\n");
    $c->write("data: $message\n\n");
  };

  # conexão DEDICADA de pub/sub para ESTA request
  my $r = Redis->new(server => $config->{redis_srv});

  my $sub_cb = sub {
    my ($rconn, $channel, $message) = @_;
    $send->($channel, $message);
  };

  $r->subscribe(['alerts','nodes','packets'], $sub_cb);

  $c->on(finish => sub {
    eval { $r->unsubscribe(['alerts','nodes','packets'], $sub_cb); $r->quit; };
  });

  $c->rendered(200);
};

# =========================
# Dashboard
# =========================
get '/dashboard' => sub ($c) { $c->render(template => 'dashboard') };

# Novo endpoint para configuração de rede
post '/api/set_network_range' => sub ($c) {
    my $p = $c->req->json // {};
    return $c->render(status=>400, json=>{ok=>\0, error=>'invalid json'}) unless ref $p eq 'HASH';
    return $c->render(status=>403, json=>{ok=>\0, error=>'forbidden'}) unless _ok_key($p->{key});

    my $range = $p->{range} || '0.0.0.0/0';
    $redis->set('network_range', $range);
    $redis->publish('config', encode_json({ type => 'network_range', value => $range }));
    $c->render(json => { ok => \1 });
};

# Upload de logo (salva no Redis)


get '/api/traffic-snapshot' => sub ($c) {
  my $row = $dbh->selectrow_hashref(q{
    SELECT
      COALESCE(SUM(CASE WHEN protocol = 6  THEN 1 ELSE 0 END), 0) AS tcp,   -- TCP
      COALESCE(SUM(CASE WHEN protocol = 17 THEN 1 ELSE 0 END), 0) AS udp,   -- UDP
      COALESCE(SUM(CASE WHEN protocol = 1  THEN 1 ELSE 0 END), 0) AS icmp   -- ICMP
    FROM packets
    WHERE "timestamp" > NOW() - INTERVAL '2 seconds'
  });
  $c->render(json => { %{$row||{}}, timestamp => scalar localtime });
};

get '/api/nodes' => sub ($c) {
  my $rows = $dbh->selectall_arrayref(q{
    SELECT node_id, hostname, status, last_seen
    FROM nodes
    WHERE last_seen > NOW() - INTERVAL '90 seconds'
    ORDER BY last_seen DESC
  }, { Slice=>{} }) || [];
  $c->render(json => { nodes => $rows });
};

get '/api/alerts' => sub ($c) {
  my $rows = $dbh->selectall_arrayref(q{
    SELECT type, severity, COUNT(*) AS count
    FROM alerts
    WHERE "timestamp" > NOW() - INTERVAL '24 hours'
    GROUP BY type, severity
    ORDER BY count DESC
  }, { Slice=>{} }) || [];
  $c->render(json => { alerts => $rows });
};


app->start('daemon', '-l', 'http://*:8080') unless caller;

__DATA__

@@ dashboard.html.ep
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>EcoBat IDS</title>
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {
      --primary: #00ffaa;
      --secondary: #0088ff;
      --dark: #0a0e17;
      --light: #e0e0e0;
    }
    body {
      font-family: 'Orbitron', sans-serif;
      background-color: var(--dark);
      color: var(--light);
      margin: 0;
      padding: 20px;
    }
    .header {
      display: flex;
      align-items: center;
      margin-bottom: 30px;
      border-bottom: 1px solid var(--primary);
      padding-bottom: 15px;
    }
    .logo {
      max-height: 60px;
      margin-right: 20px;
    }
    .card {
      background: rgba(10, 14, 23, 0.8);
      border: 1px solid var(--primary);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 25px;
      box-shadow: 0 0 15px rgba(0, 255, 170, 0.1);
    }
    h2, h3 {
      color: var(--primary);
      text-shadow: 0 0 5px rgba(0, 255, 170, 0.5);
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th {
      background: rgba(0, 136, 255, 0.2);
      color: var(--secondary);
      padding: 12px;
      text-align: left;
    }
    td {
      padding: 10px 12px;
      border-bottom: 1px solid rgba(0, 255, 170, 0.1);
    }
    tr:hover td {
      background: rgba(0, 255, 170, 0.05);
    }
    .chart-container {
      height: 300px;
      margin-top: 20px;
    }
    .controls {
      display: flex;
      gap: 15px;
      margin-bottom: 20px;
    }
    input, button, select {
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid var(--primary);
      color: var(--light);
      padding: 8px 15px;
      border-radius: 4px;
    }
    button {
      cursor: pointer;
      transition: all 0.3s;
    }
    button:hover {
      background: var(--primary);
      color: var(--dark);
    }
    .alert {
      color: #ff5555;
      font-weight: bold;
    }
  </style>
</head>
<body>
  <div class="header">
    <img id="brandLogo" src="/ecobat_logo.png?ts=1" style="height:100px;border-radius:6px">

    <h1>EcoBat IDS</h1>
  </div>

  <div class="controls">
    <select id="networkRange">
      <option value="0.0.0.0/0">Toda a Rede</option>
      <option value="192.168.1.0/24">192.168.1.0/24</option>
      <option value="10.0.0.0/8">10.0.0.0/8</option>
    </select>
    <button onclick="updateNetworkRange()">Aplicar Filtro</button>
  </div>

  <div class="card">
    <h3>📊 Estatísticas em Tempo Real</h3>
    <div class="chart-container">
      <canvas id="trafficChart"></canvas>
    </div>
  </div>

  <div class="card">
    <h3>🖥️ Active Nodes</h3>
    <table class="tbl">
  <thead>
    <tr><th>Node ID</th><th>Hostname</th><th>Status</th><th>Last Seen</th></tr>
  </thead>
  <tbody id="nodesBody"></tbody>
</table>
  </div>

  <div class="card">
    <h3>🚨 Alertas Recentes (24h)</h3>
   <table class="tbl">
  <thead>
    <tr><th>Tipo</th><th>Severidade</th><th>Contagem</th></tr>
  </thead>
  <tbody id="alertsBody"></tbody>
</table>
  </div>

<script>
// ===== Configuração Inicial =====
let trafficChart;
const ctx = document.getElementById('trafficChart').getContext('2d');
let chartData = {
  labels: [],
  datasets: [
    { label: 'TCP', data: [], borderColor: '#00ffaa', tension: 0.1 },
    { label: 'UDP', data: [], borderColor: '#0088ff', tension: 0.1 },
    { label: 'ICMP', data: [], borderColor: '#ff5555', tension: 0.1 }
  ]
};

function initChart() {
  trafficChart = new Chart(ctx, {
    type: 'line',
    data: chartData,
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: { y: { beginAtZero: true } }
    }
  });
}

// ===== Atualizações Dinâmicas =====
async function updateSection(id, url, mapper) {
  try {
    const res = await fetch(url);
    const data = await res.json();
    document.getElementById(id).innerHTML = mapper(data).join("");
  } catch (e) { console.error(e); }
}

function mapAlerts(d) {
  return (d.alerts || []).map(a => `
    <tr>
      <td>${a.type}</td>
      <td class="${a.severity === 'high' ? 'alert' : ''}">${a.severity}</td>
      <td>${a.count}</td>
    </tr>
  `);
}

function updateNetworkRange() {
  const range = document.getElementById('networkRange').value;
  fetch('/api/set_network_range', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ 
      range: range,
      key: 's3cr3t-clust3r-k3y'  // Substitua pela sua chave
    })
  });
}





// ===== Inicialização =====
document.addEventListener('DOMContentLoaded', () => {
  initChart();
  loadLogo();
  refreshAll();

  const es = new EventSource('/updates');
  es.addEventListener('packets', updateChart);
  ['alerts', 'nodes'].forEach(evt => es.addEventListener(evt, refreshAll));
});

function updateChart() {
  // Simulação - substitua por dados reais do seu backend
  const now = new Date().toLocaleTimeString();
  chartData.labels.push(now);
  chartData.datasets[0].data.push(Math.random() * 100);
  chartData.datasets[1].data.push(Math.random() * 50);
  chartData.datasets[2].data.push(Math.random() * 20);
  
  if (chartData.labels.length > 15) {
    chartData.labels.shift();
    chartData.datasets.forEach(d => d.data.shift());
  }
  
  trafficChart.update();
}

async function pump() {
  try {
    const r = await fetch('/api/traffic-snapshot'); // crie um endpoint que devolve {tcp,udp,icmp,timestamp}
    const d = await r.json();
    const now = new Date(d.timestamp).toLocaleTimeString();

    chartData.labels.push(now);
    chartData.datasets[0].data.push(d.tcp);
    chartData.datasets[1].data.push(d.udp);
    chartData.datasets[2].data.push(d.icmp);

    if (chartData.labels.length > 30) {
      chartData.labels.shift();
      chartData.datasets.forEach(ds => ds.data.shift());
    }
    trafficChart.update();
  } catch(e) { console.error(e); }
}
setInterval(pump, 2000);


async function refreshNodes() {
  try {
    const r = await fetch('/api/nodes');
    const data = await r.json();
    const tbody = document.getElementById('nodesBody');
    tbody.innerHTML = '';
    for (const n of (data.nodes || [])) {
      const tr = document.createElement('tr');
      const seen = n.last_seen || '';
      tr.innerHTML =
        `<td>${n.node_id}</td>
         <td>${n.hostname||''}</td>
         <td>${n.status||''}</td>
         <td>${seen}</td>`;
      tbody.appendChild(tr);
    }
  } catch(e) { console.error('nodes err', e); }
}

async function refreshAlerts() {
  try {
    const r = await fetch('/api/alerts');
    const data = await r.json();
    const tbody = document.getElementById('alertsBody');
    tbody.innerHTML = '';
    for (const a of (data.alerts || [])) {
      const tr = document.createElement('tr');
      tr.innerHTML =
        `<td>${a.type||''}</td>
         <td>${a.severity||''}</td>
         <td>${a.count||0}</td>`;
      tbody.appendChild(tr);
    }
  } catch(e) { console.error('alerts err', e); }
}

refreshNodes(); refreshAlerts();
setInterval(() => { refreshNodes(); refreshAlerts(); }, 2000)
</script>
</body>
</html>

