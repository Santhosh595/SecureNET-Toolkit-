/* SecureNET Control Panel - Chart.js Configurations */

document.addEventListener('DOMContentLoaded', function() {
    // Chart.js global defaults
    if (typeof Chart !== 'undefined') {
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.borderColor = '#1e2d45';
        Chart.defaults.font.family = 'Inter, sans-serif';
    }

    // Analytics page charts
    const scansCanvas = document.getElementById('chart-scans-per-tool');
    if (scansCanvas) {
        const ctx = scansCanvas.getContext('2d');
        const toolNames = scansCanvas.dataset.tools ? JSON.parse(scansCanvas.dataset.tools) : [];
        const toolCounts = scansCanvas.dataset.counts ? JSON.parse(scansCanvas.dataset.counts) : [];

        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: toolNames,
                datasets: [{
                    label: 'Scans',
                    data: toolCounts,
                    backgroundColor: [
                        '#10b981', '#3b82f6', '#8b5cf6', '#f59e0b',
                        '#ec4899', '#ef4444', '#06b6d4', '#84cc16',
                        '#f97316', '#6366f1', '#14b8a6', '#a855f7'
                    ],
                    borderRadius: 4,
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, grid: { color: '#1e2d45' } },
                    x: { grid: { display: false } }
                }
            }
        });
    }

    // Donut chart for tool usage distribution
    const donutCanvas = document.getElementById('chart-tool-usage');
    if (donutCanvas) {
        const ctx = donutCanvas.getContext('2d');
        const labels = donutCanvas.dataset.labels ? JSON.parse(donutCanvas.dataset.labels) : [];
        const values = donutCanvas.dataset.values ? JSON.parse(donutCanvas.dataset.values) : [];
        const colors = donutCanvas.dataset.colors ? JSON.parse(donutCanvas.dataset.colors) : [];

        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: colors,
                    borderWidth: 0,
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom', labels: { padding: 16 } }
                }
            }
        });
    }

    // Alert severity line chart
    const severityCanvas = document.getElementById('chart-severity-timeline');
    if (severityCanvas) {
        const ctx = severityCanvas.getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                datasets: [
                    { label: 'Critical', data: [1, 0, 2, 0, 1, 0, 0], borderColor: '#dc2626', tension: 0.3 },
                    { label: 'High', data: [3, 2, 5, 1, 4, 2, 1], borderColor: '#ef4444', tension: 0.3 },
                    { label: 'Medium', data: [5, 8, 6, 4, 7, 3, 2], borderColor: '#f59e0b', tension: 0.3 },
                ]
            },
            options: {
                responsive: true,
                plugins: { legend: { position: 'bottom' } },
                scales: {
                    y: { beginAtZero: true, grid: { color: '#1e2d45' } },
                    x: { grid: { display: false } }
                }
            }
        });
    }
});
