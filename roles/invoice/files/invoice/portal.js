const $ = id => document.getElementById(id);
async function refresh() {
  const response = await fetch('/api/status');
  if (!response.ok) throw new Error('Application status is unavailable');
  const data = await response.json();
  $('release').textContent = data.release.release_id || 'Local development';
  $('version').textContent = `PyPDF2 ${data.release.installed_version}`;
  $('deadline').textContent = `${data.timeout_seconds} seconds`;
  $('evidence').textContent = data.release.wheel_sha256 ? `Artifact SHA256: ${data.release.wheel_sha256}` : 'Development release';
  $('jobs').replaceChildren();
  for (const job of data.jobs) {
    const row = document.createElement('article');
    row.className = `job ${job.status === 'completed' ? 'success' : 'failure'}`;
    const title = document.createElement('strong');
    title.textContent = `${job.status.replaceAll('_',' ')} · ${job.elapsed_ms} ms`;
    const text = document.createElement('p');
    text.textContent = job.text || job.error || job.error_type || 'Please retry later';
    row.append(title, text);
    $('jobs').append(row);
  }
  if (!data.jobs.length) $('jobs').textContent = 'No invoices processed yet.';
}
async function processInvoice(path, body) {
  $('progress').textContent = 'Processing invoice…';
  const buttons = [...document.querySelectorAll('button,input')];
  buttons.forEach(button => button.disabled = true);
  try {
    const response = await fetch(path, {method:'POST', body, headers:body ? {'Content-Type':'application/pdf'} : {}});
    if (!response.ok) throw new Error(`Request failed (${response.status})`);
    const result = await response.json();
    $('progress').textContent = result.status === 'completed' ? 'Invoice processed successfully.' : `Processing result: ${result.status.replaceAll('_',' ')}.`;
    await refresh();
  } catch(error) { $('progress').textContent = error.message; }
  finally { buttons.forEach(button => button.disabled = false); }
}
$('sample').onclick = () => processInvoice('/api/sample');
$('regression').onclick = () => processInvoice('/api/regression');
$('upload').onchange = event => { if(event.target.files[0]) processInvoice('/api/process',event.target.files[0]); };
refresh().catch(error => $('progress').textContent = error.message);
