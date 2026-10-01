"use strict";

const byId = (id) => document.getElementById(id);
const order = ['minimal', 'elevated', 'high', 'critical'];

function cell(row, value, className) {
  const item = document.createElement('td');
  item.textContent = String(value);
  if (className) item.className = className;
  row.appendChild(item);
}

async function render() {
  const [summaryResponse, incidentsResponse] = await Promise.all([
    fetch('/api/dashboard/summary', { cache: 'no-store' }),
    fetch('/api/incidents', { cache: 'no-store' }),
  ]);
  if (!summaryResponse.ok || !incidentsResponse.ok) throw new Error('Fixture API unavailable');
  const [data, queue] = await Promise.all([summaryResponse.json(), incidentsResponse.json()]);
  if (data.dataMode !== 'synthetic-demo' || queue.dataMode !== 'synthetic-demo') throw new Error('Unexpected data source');

  byId('status').textContent = 'LOCAL API · SYNTHETIC DATA · AS OF ' + data.fixtureAsOf;
  byId('events').textContent = String(data.fleet.totalEvents);
  byId('matches').textContent = String(data.fleet.llmEvents);
  byId('unsanctioned').textContent = String(data.fleet.unsanctionedEvents);
  byId('critical').textContent = String(data.fleet.byTier.critical);

  const tiers = byId('tiers');
  const maximum = Math.max(1, ...order.map((name) => data.fleet.byTier[name]));
  for (const name of order) {
    const row = document.createElement('div');
    row.className = 'tier tier-' + name;
    const label = document.createElement('span');
    label.className = 'tier-name';
    label.textContent = name;
    const track = document.createElement('div');
    track.className = 'tier-track';
    const fill = document.createElement('span');
    fill.className = 'tier-fill';
    fill.style.width = (data.fleet.byTier[name] / maximum * 100) + '%';
    track.appendChild(fill);
    const count = document.createElement('span');
    count.className = 'tier-count';
    count.textContent = String(data.fleet.byTier[name]);
    row.append(label, track, count);
    tiers.appendChild(row);
  }

  const incidents = byId('incidents');
  for (const item of queue.incidents.slice(0, 3)) {
    const row = document.createElement('div');
    row.className = 'incident';
    const title = document.createElement('strong');
    title.textContent = item.title;
    const detail = document.createElement('small');
    detail.textContent = item.severity.toUpperCase() + ' · ' + item.status.toUpperCase() + ' · fixture only';
    row.append(title, detail);
    incidents.appendChild(row);
  }

  const departments = byId('departments');
  for (const department of data.departments) {
    const row = document.createElement('tr');
    cell(row, department.department);
    cell(row, department.llmEvents);
    cell(row, department.unsanctionedRate.toFixed(1) + '% not on sample list');
    cell(row, department.exposureScore.toFixed(1), 'score');
    cell(row, department.recommendedAction);
    departments.appendChild(row);
  }
}

render().catch(() => { byId('status').textContent = 'Fixture unavailable. Start the local API to view this console.'; });
