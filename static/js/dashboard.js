'use strict';
(async () => {
  const palette = ['#ff6577','#f5b556','#65a5ff','#48d7b4','#ae93ef','#64cedb','#d2b77d'];
  try {
    const response = await fetch('/api/charts');
    if (!response.ok) throw new Error('Chart data unavailable');
    const data = await response.json();
    Chart.defaults.color = '#9eafc4';
    Chart.defaults.font.family = 'system-ui, sans-serif';
    Chart.defaults.borderColor = '#263349';
    for (const [key,series] of Object.entries(data)) {
      const fallback = document.getElementById(`fallback-${key}`);
      fallback.textContent = series.labels.map((label,index) => `${label}: ${series.values[index]}`).join(' · ') || 'No data yet. Generate a scenario.';
      if (!series.labels.length) continue;
      const type = key === 'severity' ? 'doughnut' : key === 'events' ? 'line' : 'bar';
      new Chart(document.getElementById(`chart-${key}`), {
        type,
        data: {labels:series.labels, datasets:[{label:'Records',data:series.values,
          backgroundColor:type === 'line' ? '#48d7b425' : palette,
          borderColor:type === 'line' ? '#48d7b4' : '#152031',
          borderWidth:2,borderRadius:4,tension:0.3,fill:type === 'line',pointRadius:3}]},
        options: {responsive:true,maintainAspectRatio:false,animation:false,
          indexAxis:key === 'detection' ? 'y' : 'x',
          plugins:{legend:{display:type === 'doughnut',position:'right',labels:{boxWidth:10,padding:20}}},
          ...(type === 'doughnut' ? {cutout:'72%'} : {scales:{x:{grid:{display:false},ticks:{maxRotation:25}},y:{beginAtZero:true,ticks:{precision:0}}}})}
      });
    }
  } catch (error) {
    document.querySelectorAll('.chart-fallback').forEach(el => {el.textContent='Charts unavailable. Reload or use the Reports tables.';});
  }
})();
