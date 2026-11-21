/* Database-backed interactions for DevMonitor. */

const ITEMS_PER_PAGE = 10;
let devices = [];
let users = [];
const adminLogs = { activity: [], device: [] };
const adminLogsLoaded = { activity: false, device: false };
const adminLogsHaveMore = { activity: false, device: false };
const adminLogQueries = { activity: '', device: '' };
let selectedDeviceId = null;
let selectedUserId = null;
let devicePage = 1;
let userVisibleCount = ITEMS_PER_PAGE;
let usersLoaded = false;
let deviceDetailsRequestId = 0;
let deviceQrCountdownInterval = null;
let deviceQrStatusInterval = null;
let deviceRefreshPromise = null;
let dashboardRefreshPromise = null;
let observedRegistrationDeviceIds = null;
let latestVerificationDeviceId = undefined;
let registrationRedirectStarted = false;
let deviceSearch = '';
let deviceStatusFilter = 'all';
let archivedDeviceSearch = '';
let archivedDevices = [];
let userSearch = '';
let deviceSort = 'name-asc';
let userSort = 'name-asc';
let archivedDevicePage = 1;
const isAdministrator = document.body.dataset.isAdmin === 'true';
const deviceAddresses = new Map();
const deviceAddressRequests = new Map();
let registrationRedirectTimer = null;
let registrationRedirectInterval = null;
let registrationSuccessShown = false;

function csrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.content || '';
}

function initArchivedDevicesPage() {
    refreshArchivedDevices().catch(error => showToast(error.message, 'danger'));
    document.getElementById('archivedDeviceSearch')?.addEventListener('input', event => {
        archivedDeviceSearch = event.target.value.trim().toLowerCase();
        archivedDevicePage = 1;
        renderArchivedDevicesCards();
    });
}

async function api(url, options = {}) {
    const headers = { 'X-CSRF-Token': csrfToken(), ...(options.headers || {}) };
    if (options.body) headers['Content-Type'] = 'application/json';
    const response = await fetch(url, { credentials: 'same-origin', ...options, headers });
    if (response.status === 401) {
        window.location.assign('/');
        throw new Error('Your session has expired.');
    }
    if (response.status === 204) return null;
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `Request failed (${response.status}).`);
    return result;
}

function escapeHTML(value) {
    const element = document.createElement('span');
    element.textContent = value == null ? '' : String(value);
    return element.innerHTML;
}

function deviceStatusBadge(status) {
    const normalized = String(status || 'unknown').toLowerCase();
    const className = {
        online: 'badge-online',
        offline: 'badge-offline',
        maintenance: 'badge-maintenance',
        unknown: 'badge-unknown'
    }[normalized] || 'badge-unknown';
    const label = normalized.charAt(0).toUpperCase() + normalized.slice(1);
    return `<span class="${className}" aria-label="Device status: ${escapeHTML(label)}">${escapeHTML(label)}</span>`;
}

function showToast(message, type = 'success') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-bg-${type} border-0`;
    toast.setAttribute('role', 'status');
    toast.innerHTML = `<div class="d-flex"><div class="toast-body">${escapeHTML(message)}</div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto"
                data-bs-dismiss="toast"></button></div>`;
    container.appendChild(toast);
    const instance = new bootstrap.Toast(toast, { delay: 3500 });
    toast.addEventListener('hidden.bs.toast', () => toast.remove());
    instance.show();
}

function showRegistrationSuccess(device = null) {
    const modalRoot = document.getElementById('deviceRegistrationSuccessModal');
    if (registrationSuccessShown || !modalRoot) return;
    registrationSuccessShown = true;
    registrationRedirectStarted = false;
    const detailsButton = modalRoot.querySelector('#deviceRegistrationDetailsButton');
    if (device?.id != null && detailsButton) {
        detailsButton.href = device.specifications_url
            || `/devices/${encodeURIComponent(device.id)}/specifications`;
    }
    const redirect = destination => {
        window.clearTimeout(registrationRedirectTimer);
        window.clearInterval(registrationRedirectInterval);
        if (registrationRedirectStarted) return;
        registrationRedirectStarted = true;
        window.location.assign(destination);
    };
    modalRoot.querySelector('#deviceScanDashboardButton').addEventListener('click', event => {
        event.preventDefault();
        redirect('/dashboard');
    }, { once: true });
    detailsButton?.addEventListener('click', event => {
        event.preventDefault();
        redirect(detailsButton.href);
    }, { once: true });
    modalRoot.addEventListener('hidden.bs.modal', () => {
        window.clearTimeout(registrationRedirectTimer);
        window.clearInterval(registrationRedirectInterval);
        registrationRedirectStarted = true;
    }, { once: true });
    const countdown = modalRoot.querySelector('#deviceRegistrationCountdown');
    let remaining = 5;
    bootstrap.Modal.getOrCreateInstance(modalRoot).show();
    registrationRedirectInterval = window.setInterval(() => {
        remaining -= 1;
        if (countdown) {
            countdown.textContent = `Redirecting to Dashboard in ${remaining} seconds...`;
        }
        if (remaining <= 0) redirect('/dashboard');
    }, 1000);
}

function initSidebar() {
    const toggle = document.getElementById('sidebarToggle');
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    if (!toggle || !sidebar || !overlay) return;
    const close = () => {
        sidebar.classList.remove('show');
        overlay.classList.remove('show');
    };
    toggle.addEventListener('click', () => {
        sidebar.classList.toggle('show');
        overlay.classList.toggle('show');
    });
    overlay.addEventListener('click', close);
}

function getCurrentPage() {
    const path = window.location.pathname;
    if (path.includes('device-verification')) return 'device-verification';
    if (path.includes('archived-devices')) return 'archived-devices';
    if (path.includes('dashboard')) return 'dashboard';
    if (path.includes('devices')) return 'devices';
    if (path.includes('admin')) return 'admin';
    return 'login';
}

function renderPagination(containerId, total, current, onPage) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const pages = Math.ceil(total / ITEMS_PER_PAGE);
    if (pages <= 1) {
        container.innerHTML = '';
        return;
    }
    container.innerHTML = Array.from({ length: pages }, (_, index) => {
        const page = index + 1;
        return `<li class="page-item ${page === current ? 'active' : ''}">
            <button class="page-link" data-page="${page}">${page}</button></li>`;
    }).join('');
    container.querySelectorAll('[data-page]').forEach(button => {
        button.addEventListener('click', () => onPage(Number(button.dataset.page)));
    });
}

function sortRows(rows, key, nameKey, statusKey = 'status') {
    return [...rows].sort((a, b) => {
        if (key === 'name-desc') return b[nameKey].localeCompare(a[nameKey]);
        if (key === 'status-asc') return a[statusKey].localeCompare(b[statusKey]);
        if (key === 'status-desc') return b[statusKey].localeCompare(a[statusKey]);
        if (key === 'role-asc') return a.role.localeCompare(b.role);
        if (key === 'date-desc') return b.registered.localeCompare(a.registered);
        if (key === 'date-asc') return a.registered.localeCompare(b.registered);
        if (key === 'type-asc') return a.type.localeCompare(b.type);
        return a[nameKey].localeCompare(b[nameKey]);
    });
}

async function refreshDevices() {
    if (deviceRefreshPromise) return deviceRefreshPromise;
    deviceRefreshPromise = api('/api/devices', { cache: 'no-store' }).then(result => {
        devices = result;
        const registered = devices.filter(device => device.isVerified);
        const currentIds = new Set(registered.map(device => device.id));
        if (observedRegistrationDeviceIds !== null && !registrationSuccessShown) {
            const newlyRegistered = registered.find(
                device => !observedRegistrationDeviceIds.has(device.id)
            );
            if (newlyRegistered) showRegistrationSuccess(newlyRegistered);
        }
        observedRegistrationDeviceIds = currentIds;
        deviceAddresses.clear();
        renderDevicesCards();
    }).finally(() => {
        deviceRefreshPromise = null;
    });
    return deviceRefreshPromise;
}

function renderDevicesCards() {
    const grid = document.getElementById('devicesCardGrid');
    if (!grid) return;
    let rows = devices.filter(device =>
        device.name.toLowerCase().includes(deviceSearch)
        && (deviceStatusFilter === 'all'
            || device.status.toLowerCase() === deviceStatusFilter)
    );
    rows = sortRows(rows, deviceSort, 'name');
    const start = (devicePage - 1) * ITEMS_PER_PAGE;
    const pageRows = rows.slice(start, start + ITEMS_PER_PAGE);
    grid.innerHTML = pageRows.length ? pageRows.map(device => `
        <article class="device-card">
            <div class="device-card-header">
                <div class="device-card-icon" aria-hidden="true"><i class="bi bi-laptop"></i></div>
                ${deviceStatusBadge(device.status)}
            </div>
            <h3 class="device-card-title">${escapeHTML(device.name)}</h3>
            <p class="device-card-subtitle">${escapeHTML(device.type)}</p>
            <div class="device-card-details">
                <div class="device-card-detail">
                    <span class="device-card-label">IP Address</span>
                    <span class="device-card-value" data-device-address="${device.id}">
                        ${escapeHTML(deviceAddresses.get(device.id) || 'Loading...')}
                    </span>
                </div>
                <div class="device-card-detail">
                    <span class="device-card-label">Operating System</span>
                    <span class="device-card-value">${escapeHTML(device.os || 'Not reported')}</span>
                </div>
                <div class="device-card-detail">
                    <span class="device-card-label">Processor</span>
                    <span class="device-card-value">${escapeHTML(device.cpu || 'Not reported')}</span>
                </div>
                <div class="device-card-detail">
                    <span class="device-card-label">RAM</span>
                    <span class="device-card-value">${escapeHTML(device.ram || 'Not reported')}</span>
                </div>
                <div class="device-card-detail">
                    <span class="device-card-label">Storage</span>
                    <span class="device-card-value">${escapeHTML(device.storage || 'Not reported')}</span>
                </div>
                <div class="device-card-detail">
                    <span class="device-card-label">Date Registered</span>
                    <span class="device-card-value">
                        ${escapeHTML(device.registered ? new Date(device.registered).toLocaleDateString() : 'Not available')}
                    </span>
                </div>
            </div>
            <div class="device-card-actions">
                <button class="btn btn-sm btn-outline-info" title="View" aria-label="View device"
                    onclick="openDeviceModal('view', ${device.id})"><i class="bi bi-eye"></i></button>
                <button class="btn btn-sm btn-outline-primary" title="Edit" aria-label="Edit device"
                    onclick="openDeviceModal('edit', ${device.id})"><i class="bi bi-pencil"></i></button>
                <button class="btn btn-sm btn-outline-danger" title="Archive" aria-label="Archive device"
                    onclick="confirmDeleteDevice(${device.id})"><i class="bi bi-archive"></i></button>
                ${isAdministrator ? `<button class="btn btn-sm btn-outline-danger" title="Soft delete"
                    aria-label="Soft delete device"
                    onclick="softDeleteDevice(${device.id})"><i class="bi bi-trash"></i></button>` : ''}
            </div>
        </article>`).join('') : '<div class="device-card-empty">No devices found.</div>';
    renderPagination('devicesPagination', rows.length, devicePage, page => {
        devicePage = page;
        renderDevicesCards();
    });

    pageRows.forEach(device => loadDeviceAddress(device));
}

async function refreshArchivedDevices() {
    archivedDevices = await api('/api/archived-devices');
    renderArchivedDevicesCards();
}

function renderArchivedDevicesCards() {
    const grid = document.getElementById('archivedDevicesCardGrid');
    if (!grid) return;
    const rows = archivedDevices.filter(device =>
        `${device.name} ${device.type}`.toLowerCase().includes(archivedDeviceSearch)
    );
    const start = (archivedDevicePage - 1) * ITEMS_PER_PAGE;
    const pageRows = rows.slice(start, start + ITEMS_PER_PAGE);
    grid.innerHTML = pageRows.length ? pageRows.map(device => `
        <article class="device-card">
            <div class="device-card-header">
                <div class="device-card-icon" aria-hidden="true"><i class="bi bi-laptop"></i></div>
                <span class="badge-archived">Archived</span>
            </div>
            <h3 class="device-card-title">${escapeHTML(device.name)}</h3>
            <p class="device-card-subtitle">${escapeHTML(device.type)}</p>
            <div class="device-card-details">
                <div class="device-card-detail">
                    <span class="device-card-label">Operating System</span>
                    <span class="device-card-value">${escapeHTML(device.os || 'Not reported')}</span>
                </div>
                <div class="device-card-detail">
                    <span class="device-card-label">Archived On</span>
                    <span class="device-card-value">${escapeHTML(device.archivedAt
                        ? new Date(device.archivedAt).toLocaleString() : 'Not available')}</span>
                </div>
            </div>
            <div class="device-card-actions">
                <button class="btn btn-sm btn-outline-info" title="View" aria-label="View device"
                    onclick="openDeviceModal('view', ${device.id})"><i class="bi bi-eye"></i></button>
                <button class="btn btn-sm btn-outline-success" title="Restore" aria-label="Restore device"
                    onclick="restoreArchivedDevice(${device.id})"><i class="bi bi-arrow-counterclockwise"></i></button>
                ${isAdministrator ? `<button class="btn btn-sm btn-outline-danger" title="Soft delete"
                    aria-label="Soft delete device"
                    onclick="softDeleteDevice(${device.id})"><i class="bi bi-trash"></i></button>` : ''}
            </div>
        </article>`).join('') : '<div class="device-card-empty">No archived devices found.</div>';
    renderPagination('archivedDevicesPagination', rows.length, archivedDevicePage, page => {
        archivedDevicePage = page;
        renderArchivedDevicesCards();
    });
}

function loadDeviceAddress(device) {
    if (deviceAddresses.has(device.id) || deviceAddressRequests.has(device.id)) return;
    const request = api(`/api/devices/${device.id}/history`)
        .then(history => {
            const latestAddress = history.network?.find(record => record.ip_address)?.ip_address;
            deviceAddresses.set(device.id, latestAddress || 'Not reported');
        })
        .catch(error => {
            deviceAddresses.set(device.id, 'Unavailable');
            showToast(`Could not load the IP address for ${device.name}: ${error.message}`, 'danger');
        })
        .finally(() => {
            deviceAddressRequests.delete(device.id);
            renderDevicesCards();
        });
    deviceAddressRequests.set(device.id, request);
}

function initDevicesPage() {
    refreshDevices().catch(error => showToast(error.message, 'danger'));
    window.setInterval(() => {
        if (document.hidden) return;
        refreshDevices().catch(error => {
            showToast(`Could not refresh device information: ${error.message}`, 'danger');
        });
        const detailsView = document.getElementById('deviceDetailsView');
        if (selectedDeviceId && detailsView && !detailsView.classList.contains('d-none')) {
            api(`/api/devices/${selectedDeviceId}`, { cache: 'no-store' })
                .then(details => {
                    if (detailsView === document.getElementById('deviceDetailsView')) {
                        detailsView.innerHTML = renderDeviceDetails(details);
                    }
                })
                .catch(error => showToast(`Could not refresh device status: ${error.message}`, 'danger'));
        }
    }, 5000);
    document.getElementById('deviceSearchInput')?.addEventListener('input', event => {
        deviceSearch = event.target.value.trim().toLowerCase();
        devicePage = 1;
        renderDevicesCards();
    });
    document.getElementById('deviceSortSelect')?.addEventListener('change', event => {
        deviceSort = event.target.value;
        renderDevicesCards();
    });
    document.getElementById('deviceStatusFilter')?.addEventListener('change', event => {
        deviceStatusFilter = event.target.value;
        devicePage = 1;
        renderDevicesCards();
    });
    initDeviceQrControls();
}

function initDeviceQrControls() {
    const qrModalElement = document.getElementById('deviceRegistrationQrModal');
    if (qrModalElement) {
        const qrModal = bootstrap.Modal.getOrCreateInstance(qrModalElement);
        document.getElementById('generateDeviceQrBtn')?.addEventListener('click', () => {
            qrModal.show();
            generateDeviceRegistrationQr();
        });
        document.getElementById('createDeviceQrBtn')?.addEventListener(
            'click',
            generateDeviceRegistrationQr
        );
        document.getElementById('copyDeviceQrLinkBtn')?.addEventListener(
            'click',
            copyDeviceRegistrationLink
        );
        return;
    }

    document.getElementById('createDeviceQrBtn')?.addEventListener(
        'click',
        generateDeviceRegistrationQr
    );
    document.getElementById('copyDeviceQrLinkBtn')?.addEventListener(
        'click',
        copyDeviceRegistrationLink
    );
}

async function refreshDeviceVerificationStatus() {
    const status = document.getElementById('deviceVerificationMessage');
    try {
        const result = await api('/api/device-verification-status');
        const latest = result.latest_device;
        if (latestVerificationDeviceId === undefined) {
            latestVerificationDeviceId = latest?.id ?? null;
        } else if (
            latest?.id != null
            && latestVerificationDeviceId != null
            && latest.id !== latestVerificationDeviceId
            && !registrationSuccessShown
        ) {
            showRegistrationSuccess(latest);
        } else if (latest?.id != null && latestVerificationDeviceId == null) {
            showRegistrationSuccess(latest);
        }
        if (latest?.id != null) latestVerificationDeviceId = latest.id;
        if (!result.verified) return;

        document.getElementById('deviceVerificationPending')?.classList.add('d-none');
        document.getElementById('deviceVerificationComplete')?.classList.remove('d-none');
        document.getElementById('deviceVerificationQrPanel')?.classList.remove('d-none');
        document.querySelectorAll('#deviceRegistrationProgress .list-group-item')
            .forEach(item => item.classList.add('list-group-item-success'));
        status.textContent =
            `${result.verified_devices} verified device${result.verified_devices === 1 ? '' : 's'} linked to your account.`;
    } catch (error) {
        status.textContent = `Unable to check device verification: ${error.message}`;
    }
}

function initDeviceVerificationPage() {
    initDeviceQrControls();
    const qrCard = document.getElementById('deviceQrCard');
    if (qrCard && !qrCard.classList.contains('d-none') && qrCard.dataset.enrollmentUrl) {
        const token = new URL(qrCard.dataset.enrollmentUrl, window.location.origin)
            .pathname.split('/').pop();
        startDeviceQrCountdown(qrCard.dataset.expiresAt, qrCard.dataset.serverTime, token);
    }
    refreshDeviceVerificationStatus();
    window.setInterval(() => {
        if (!document.hidden) refreshDeviceVerificationStatus();
    }, 4000);
}

async function openDeviceModal(mode, deviceId) {
    const device = devices.find(item => item.id === deviceId);
    const requestId = ++deviceDetailsRequestId;
    selectedDeviceId = deviceId || null;
    const form = document.getElementById('deviceForm');
    form.reset();
    const detailsView = document.getElementById('deviceDetailsView');
    detailsView.classList.toggle('d-none', mode !== 'view');
    detailsView.innerHTML = mode === 'view'
        ? '<div class="device-information-empty">Loading device information...</div>'
        : '';
    form.classList.toggle('d-none', mode === 'view');
    document.getElementById('deviceFormMode').value = mode;
    document.getElementById('deviceFormId').value = deviceId || '';
    document.getElementById('deviceFormOwner').value =
        document.getElementById('currentUserDisplay')?.textContent || '';
    document.getElementById('deviceModalTitle').textContent =
        mode === 'add' ? 'Register Device' : mode === 'view' ? 'Device Details' : 'Edit Device';
    if (device) {
        document.getElementById('deviceFormName').value = device.name;
        document.getElementById('deviceFormHostname').value = device.hostname;
        document.getElementById('deviceFormType').value = device.type;
        document.getElementById('deviceFormOS').value = device.os;
        document.getElementById('deviceFormCPU').value = device.cpu;
        document.getElementById('deviceFormRAM').value = device.ram;
        document.getElementById('deviceFormStorage').value = device.storage;
        document.getElementById('deviceFormOwner').value = device.owner;
        document.getElementById('deviceFormStatus').value = device.status.toLowerCase();
    }
    const readOnly = mode === 'view';
    ['deviceFormName', 'deviceFormHostname', 'deviceFormType', 'deviceFormOS',
        'deviceFormStatus', 'deviceFormOwner'].forEach(id => {
        document.getElementById(id).disabled = readOnly || id === 'deviceFormOwner';
    });
    document.getElementById('saveDeviceBtn').classList.toggle('d-none', readOnly);
    document.getElementById('deviceModalFooter').querySelector('.btn-secondary').textContent =
        readOnly ? 'Close' : 'Cancel';
    const modal = bootstrap.Modal.getOrCreateInstance(document.getElementById('deviceModal'));
    modal.show();
    if (mode === 'view') {
        try {
            const details = await api(`/api/devices/${deviceId}`);
            if (requestId !== deviceDetailsRequestId || selectedDeviceId !== deviceId) return;
            detailsView.innerHTML = renderDeviceDetails(details);
        } catch (error) {
            if (requestId !== deviceDetailsRequestId) return;
            detailsView.innerHTML = `<div class="alert alert-danger mb-0" role="alert">
                ${escapeHTML(error.message)}
            </div>`;
        }
    }
}

function renderDeviceDetails(device) {
    const displayBytes = bytes => `${Number(bytes).toLocaleString()} bytes`;
    const value = item => {
        if (item == null || item === '') return 'Not available';
        if (Array.isArray(item)) {
            return item.map(value).join(', ') || 'None detected';
        }
        if (typeof item === 'object') {
            if ('name' in item && 'total_bytes' in item) {
                return `${item.name}: ${displayBytes(item.total_bytes)} total, ${
                    displayBytes(item.available_bytes)
                } available`;
            }
            return JSON.stringify(item);
        }
        return String(item);
    };
    const card = (label, item) => `
        <div class="device-information-card">
            <span class="device-information-label">${escapeHTML(label)}</span>
            <span class="device-information-value">${
                ['Device Status', 'Status'].includes(label)
                    ? deviceStatusBadge(item)
                    : escapeHTML(value(item))
            }</span>
        </div>`;
    const section = (title, items) => {
        const visibleItems = items.length ? items : [['Information', 'No records available']];
        return `
            <section class="device-information-section">
                <h6 class="device-information-heading">${escapeHTML(title)}</h6>
                <div class="device-information-grid">${visibleItems.map(([label, item]) => card(label, item)).join('')}</div>
            </section>`;
    };
    const owner = device.owner || {};
    const registrant = device.registered_by || {};
    const specification = device.specification || {};
    if (device.view_mode === 'user') {
        return section('Device Information', [
            ['Device Name', device.device_name],
            ['Device Type', device.device_type],
            ['MAC Address', device.mac_address],
            ['Operating System', device.operating_system],
            ['Device Status', device.status],
            ['IP Address', device.ip_address],
            ['Date Registered', device.registered_at],
        ]) + section('Device Specifications', [
            ['CPU Name', specification.cpu_model], ['Number of CPU Cores', specification.cpu_cores],
            ['RAM Capacity', specification.memory_bytes],
            ['RAM Usage', specification.ram_usage_bytes],
            ['Storage Devices', specification.storage_devices],
            ['Total Storage Capacity', specification.storage_bytes],
            ['Available Storage Capacity', specification.storage_available_bytes],
            ['GPU Information', specification.gpu_model],
            ['Motherboard Brand', specification.motherboard_brand || specification.motherboard_model],
            ['Operating System Name', specification.operating_system_name || device.operating_system],
            ['Operating System Version', specification.operating_system_version],
            ['IP Addresses', specification.ip_addresses || [device.ip_address]],
        ]) + `<p class="mt-3 mb-0"><a class="btn btn-sm btn-outline-primary"
             href="/devices/${encodeURIComponent(device.id || selectedDeviceId)}/specifications">
             View detected device specifications</a></p>`;
    }
    const sections = [
        section('Device', [
            ['Device ID', device.id], ['Asset Tag', device.asset_tag],
            ['Device Name', device.device_name], ['Hostname', device.hostname],
            ['Type', device.device_type], ['Status', device.status],
            ['MAC Address', device.mac_address],
            ['Owner User ID', device.owner_user_id],
            ['Registered By User ID', device.registered_by_user_id],
            ['Lifecycle', device.lifecycle_status],
            ['Archived At', device.archived_at],
            ['Archived By User ID', device.archived_by_user_id],
            ['Deleted At', device.deleted_at],
            ['Serial Number', device.serial_number], ['Manufacturer', device.manufacturer],
            ['Model', device.model], ['Operating System', device.operating_system],
            ['OS Version', device.operating_system_version],
            ['Registered At', device.registered_at], ['Updated At', device.updated_at],
            ['Last Seen At', device.last_seen_at],
        ]),
        section('Ownership and Dates', [
            ['Owner', owner.full_name], ['Owner Username', owner.username],
            ['Owner Email', owner.email], ['Registered By', registrant.full_name],
            ['Registered By Username', registrant.username],
            ['Registered By Email', registrant.email],
        ]),
        section('Hardware Specification', [
            ['Device ID', specification.device_id],
            ['CPU Name', specification.cpu_model], ['CPU Cores', specification.cpu_cores],
            ['CPU Threads', specification.cpu_threads], ['Memory (bytes)', specification.memory_bytes],
            ['RAM Usage (bytes)', specification.ram_usage_bytes],
            ['Storage Devices', specification.storage_devices],
            ['Storage (bytes)', specification.storage_bytes],
            ['Available Storage (bytes)', specification.storage_available_bytes],
            ['GPU Information', specification.gpu_model],
            ['BIOS Version', specification.bios_version],
            ['Motherboard Brand', specification.motherboard_brand || specification.motherboard_model],
            ['Operating System Name', specification.operating_system_name],
            ['Specification OS Version', specification.operating_system_version],
            ['IP Addresses', specification.ip_addresses],
            ['Collected At', specification.collected_at],
        ]),
        section('Network Records', (device.network_records || []).flatMap(record => [
            ['Record ID', record.id], ['Device ID', record.device_id],
            ['IP Address', record.ip_address], ['Subnet Mask', record.subnet_mask],
            ['Default Gateway', record.default_gateway], ['DNS Server', record.dns_server],
            ['Connectivity', record.connectivity_status], ['Recorded At', record.recorded_at],
        ])),
        section('Network Interfaces', (device.network_interfaces || []).flatMap(networkInterface => [
            ['Interface ID', networkInterface.id], ['Device ID', networkInterface.device_id],
            ['Interface', networkInterface.interface_name], ['MAC Address', networkInterface.mac_address],
            ['Interface Type', networkInterface.interface_type],
            ['Primary', networkInterface.is_primary ? 'Yes' : 'No'],
            ['Created At', networkInterface.created_at],
            ...networkInterface.observations.flatMap(observation => [
                ['Observation ID', observation.id], ['Interface ID', observation.interface_id],
                ['Observed IP Address', observation.ip_address],
                ['Subnet Prefix', observation.subnet_prefix], ['Gateway', observation.gateway],
                ['DNS Servers', JSON.stringify(observation.dns_servers)],
                ['SSID', observation.ssid], ['Connection Type', observation.connection_type],
                ['Observed At', observation.observed_at],
            ]),
        ])),
        section('Device Scan History', (device.scanner_runs || []).flatMap(run => [
            ['Run ID', run.id], ['Device ID', run.device_id],
            ['Initiated By ID', run.initiated_by_user_id],
            ['Initiated By', run.initiated_by?.full_name || run.initiated_by?.username],
            ['Scan Status', run.status], ['Summary', run.summary],
            ['Detected Problem', run.detected_problem], ['Recommendation', run.recommendation],
            ['Started At', run.started_at], ['Finished At', run.finished_at],
            ...run.checks.flatMap(check => [
                ['Check ID', check.id], ['Run ID', check.run_id],
                ['Check', check.check_name], ['Category', check.category],
                ['Check Status', check.status], ['Result', check.result_summary],
                ['Details', JSON.stringify(check.details)], ['Measured At', check.measured_at],
            ]),
        ])),
        section('Monitoring Metrics', (device.metrics || []).flatMap(metric => [
            ['Metric ID', metric.id], ['Device ID', metric.device_id],
            ['CPU Usage (%)', metric.cpu_percent], ['Memory Usage (%)', metric.memory_percent],
            ['Storage Usage (%)', metric.storage_percent],
            ['Memory Used (bytes)', metric.memory_used_bytes],
            ['Storage Used (bytes)', metric.storage_used_bytes],
            ['Network Received (bytes)', metric.network_rx_bytes],
            ['Network Sent (bytes)', metric.network_tx_bytes],
            ['Collected At', metric.collected_at],
        ])),
        section('System Logs', (device.logs || []).flatMap(log => [
            ['Log ID', log.id], ['Device ID', log.device_id],
            ['Event', log.event], ['Timestamp', log.timestamp],
        ])),
        section('Activity History', (device.activity_logs || []).flatMap(entry => [
            ['Activity ID', entry.id], ['Actor User ID', entry.actor_user_id],
            ['Event', entry.event], ['Entity', entry.entity_type],
            ['Actor', entry.actor], ['Details', JSON.stringify(entry.details)],
            ['Occurred At', entry.occurred_at],
        ])),
    ];
    return sections.join('') + `<p class="mt-3 mb-0"><a class="btn btn-sm btn-outline-primary"
        href="/devices/${encodeURIComponent(device.id || selectedDeviceId)}/specifications">
        View detected device specifications</a></p>`;
}

async function generateDeviceRegistrationQr() {
    registrationSuccessShown = false;
    registrationRedirectStarted = false;
    window.clearTimeout(registrationRedirectTimer);
    window.clearInterval(registrationRedirectInterval);
    const button = document.getElementById('createDeviceQrBtn');
    const qrCard = document.getElementById('deviceQrCard');
    const image = document.getElementById('deviceRegistrationQrImage');
    const link = document.getElementById('deviceRegistrationQrLink');
    const copyButton = document.getElementById('copyDeviceQrLinkBtn');
    const status = document.getElementById('deviceQrStatus');
    const expiryCard = document.getElementById('deviceQrExpiryCard');
    button.disabled = true;
    clearInterval(deviceQrCountdownInterval);
    clearInterval(deviceQrStatusInterval);
    qrCard.classList.add('d-none');
    link.classList.add('d-none');
    copyButton.classList.add('d-none');
    expiryCard.classList.add('d-none');
    button.textContent = 'Generate QR Code';
    status.textContent = 'Creating a secure one-use registration code...';
    try {
        const result = await api('/api/device-registration-tokens', { method: 'POST' });
        image.src = result.qr_code;
        qrCard.classList.remove('d-none');
        link.href = result.enrollment_url;
        link.classList.remove('d-none');
        copyButton.classList.remove('d-none');
        expiryCard.classList.remove('d-none');
        status.textContent = 'Your QR code is ready.';
        button.textContent = 'Regenerate QR Code';
        const token = new URL(result.enrollment_url, window.location.origin)
            .pathname.split('/').pop();
        startDeviceQrCountdown(result.expires_at, result.server_time, token);
    } catch (error) {
        status.textContent = error.message;
        showToast(error.message, 'danger');
    } finally {
        button.disabled = false;
    }
}

function startDeviceQrCountdown(expiresAt, serverTime, token) {
    let expiration = new Date(expiresAt).getTime();
    let serverClockOffset = Date.now() - new Date(serverTime).getTime();
    const remaining = document.getElementById('deviceQrRemainingTime');
    const expiryStatus = document.getElementById('deviceQrExpiryStatus');
    const tokenStatus = document.getElementById('deviceQrTokenStatus');
    const createButton = document.getElementById('createDeviceQrBtn');
    const link = document.getElementById('deviceRegistrationQrLink');
    const copyButton = document.getElementById('copyDeviceQrLinkBtn');

    const updateCountdown = () => {
        const serverNow = Date.now() - serverClockOffset;
        const seconds = Math.max(0, Math.ceil((expiration - serverNow) / 1000));
        const minutes = Math.floor(seconds / 60);
        const displaySeconds = String(seconds % 60).padStart(2, '0');
        remaining.textContent = `${minutes}:${displaySeconds}`;

        if (seconds === 0) {
            clearInterval(deviceQrCountdownInterval);
            clearInterval(deviceQrStatusInterval);
            expiryStatus.textContent = 'Expired';
            tokenStatus.textContent = 'Expired';
            link.classList.add('d-none');
            copyButton.classList.add('d-none');
            createButton.textContent = 'Regenerate QR Code';
            document.getElementById('deviceQrStatus').textContent =
                'This QR code has expired. Generate a new one to continue.';
            return;
        }

        expiryStatus.textContent = new Date(expiration).toLocaleTimeString();
        tokenStatus.textContent = 'Unused';
    };

    const refreshStatus = async () => {
        const result = await api(
            `/api/device-registration-tokens/${encodeURIComponent(token)}/status`
        );
        serverClockOffset = Date.now() - new Date(result.server_time).getTime();
        expiration = new Date(result.expires_at).getTime();
        if (result.status === 'active') {
            tokenStatus.textContent = 'Unused';
            updateCountdown();
            return;
        }

        if (result.status === 'verified' || result.status === 'download_confirmed') {
            tokenStatus.textContent = result.status === 'verified'
                ? 'Account verified'
                : 'Download confirmed';
            expiryStatus.textContent = 'Awaiting device registration';
            remaining.textContent = `${Math.max(0, Math.ceil((expiration - (Date.now() - serverClockOffset)) / 1000))}s`;
            document.getElementById('deviceQrStatus').textContent =
                result.status === 'verified'
                    ? 'Account verified. Confirm the Windows EXE download on the scanned device.'
                    : 'Download confirmed. Run the Device Agent EXE and approve device registration.';
            return;
        }

        clearInterval(deviceQrCountdownInterval);
        clearInterval(deviceQrStatusInterval);
        remaining.textContent = result.status === 'used' ? 'Complete' : '00:00';
        expiryStatus.textContent = result.status === 'used'
            ? 'Registration complete'
            : result.status === 'revoked' ? 'Revoked' : 'Expired';
        tokenStatus.textContent = result.status === 'used'
            ? 'Used'
            : result.status === 'revoked' ? 'Revoked' : 'Expired';
        link.classList.add('d-none');
        copyButton.classList.add('d-none');
        createButton.textContent = 'Generate New QR Code';
        document.getElementById('deviceQrStatus').textContent =
            result.status === 'used'
                ? 'This QR code has been used to register a device.'
                : `This QR code is ${result.status}. Generate a new one to continue.`;
        if (result.status === 'used') showRegistrationSuccess(result.device);
    };

    updateCountdown();
    tokenStatus.textContent = 'Unused';
    deviceQrCountdownInterval = setInterval(updateCountdown, 1000);
    refreshStatus().catch(error => {
        clearInterval(deviceQrStatusInterval);
        tokenStatus.textContent = 'Unavailable';
        showToast(`Unable to verify the QR code status: ${error.message}`, 'danger');
    });
    deviceQrStatusInterval = setInterval(() => {
        refreshStatus().catch(error => {
            clearInterval(deviceQrStatusInterval);
            tokenStatus.textContent = 'Unavailable';
            showToast(`Unable to verify the QR code status: ${error.message}`, 'danger');
        });
    }, 10000);
}

async function copyDeviceRegistrationLink() {
    const link = document.getElementById('deviceRegistrationQrLink');
    try {
        await navigator.clipboard.writeText(link.href);
        showToast('Registration link copied.');
    } catch (error) {
        showToast('Unable to copy the registration link in this browser.', 'danger');
    }
}

async function saveDevice() {
    const mode = document.getElementById('deviceFormMode').value;
    const data = {
        name: document.getElementById('deviceFormName').value.trim(),
        hostname: document.getElementById('deviceFormHostname').value.trim(),
        type: document.getElementById('deviceFormType').value,
        os: document.getElementById('deviceFormOS').value,
        status: document.getElementById('deviceFormStatus').value
    };
    if (!data.name || !data.type || !data.os) {
        showToast('Device name, type, and operating system are required.', 'danger');
        return;
    }
    try {
        await api(mode === 'add' ? '/api/devices' : `/api/devices/${selectedDeviceId}`, {
            method: mode === 'add' ? 'POST' : 'PATCH',
            body: JSON.stringify(data)
        });
        bootstrap.Modal.getInstance(document.getElementById('deviceModal')).hide();
        await refreshDevices();
        showToast(mode === 'add' ? 'Device registered.' : 'Device updated.');
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

function confirmDeleteDevice(deviceId) {
    selectedDeviceId = deviceId;
    const device = devices.find(item => item.id === deviceId);
    document.getElementById('deleteDeviceName').textContent = device?.name || '';
    bootstrap.Modal.getOrCreateInstance(document.getElementById('deleteDeviceModal')).show();
}

async function archiveSelectedDevice() {
    try {
        await api(`/api/devices/${selectedDeviceId}/archive`, { method: 'POST' });
        bootstrap.Modal.getInstance(document.getElementById('deleteDeviceModal')).hide();
        await refreshDevices();
        showToast('Device archived; its history was retained.');
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

async function restoreArchivedDevice(deviceId) {
    try {
        await api(`/api/devices/${deviceId}/restore`, { method: 'POST' });
        await refreshArchivedDevices();
        showToast('Device restored to the active list.');
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

async function softDeleteDevice(deviceId) {
    if (!isAdministrator || !window.confirm('Mark this device as deleted? Its records will be retained.')) {
        return;
    }
    try {
        await api(`/api/devices/${deviceId}`, { method: 'DELETE' });
        if (getCurrentPage() === 'archived-devices') {
            await refreshArchivedDevices();
        } else {
            await refreshDevices();
        }
        showToast('Device marked deleted; its database records were retained.');
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

function healthColor(score) {
    if (score == null) return '#64748b';
    if (score >= 80) return '#16a34a';
    if (score >= 60) return '#eab308';
    if (score >= 40) return '#f97316';
    return '#dc2626';
}

function healthLabel(score) {
    if (score == null) return 'Not assessed';
    if (score >= 80) return 'Excellent';
    if (score >= 60) return 'Warning';
    if (score >= 40) return 'Attention needed';
    return 'Critical';
}

function renderHealthGauge(label, score) {
    const value = Number.isInteger(score) ? score : null;
    const color = healthColor(value);
    const percentage = value == null ? 0 : value;
    return `<div class="health-gauge-card">
        <div class="health-gauge" role="img"
            aria-label="${escapeHTML(label)} health: ${value == null ? 'not assessed' : `${value} percent, ${healthLabel(value)}`}"
            style="--health-color:${color};--health-score:${percentage}">
            <span>${value == null ? 'Not assessed' : `${value}%`}</span>
        </div>
        <div class="health-gauge-label">${escapeHTML(label)}</div>
        <div class="health-gauge-status" style="color:${color}">${healthLabel(value)}</div>
    </div>`;
}

async function refreshUsers() {
    const body = document.getElementById('usersTableBody');
    if (body) {
        body.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">Loading users...</td></tr>';
    }
    try {
        users = await api('/api/users');
        usersLoaded = true;
        userVisibleCount = ITEMS_PER_PAGE;
        renderUsersTable();
    } catch (error) {
        if (body) {
            body.innerHTML = '<tr><td colspan="7" class="text-center text-danger py-4">Unable to load users. Try reopening this section.</td></tr>';
        }
        throw error;
    }
}

function renderUsersTable() {
    const body = document.getElementById('usersTableBody');
    if (!body) return;
    let rows = users.filter(user =>
        `${user.fullName} ${user.username} ${user.email}`.toLowerCase().includes(userSearch)
    );
    rows = sortRows(rows, userSort, 'fullName');
    const pageRows = rows.slice(0, userVisibleCount);
    body.innerHTML = pageRows.length ? pageRows.map(user => `
        <tr>
            <td>${user.id}</td><td>${escapeHTML(user.fullName)}</td>
            <td>${escapeHTML(user.username)}</td><td>${escapeHTML(user.email)}</td>
            <td>${escapeHTML(user.role)}</td><td>${escapeHTML(user.status)}</td>
            <td class="text-center"><div class="action-btn-group justify-content-center">
                <button class="btn btn-sm btn-outline-primary" title="Edit"
                    onclick="openUserModal('edit', ${user.id})"><i class="bi bi-pencil"></i></button>
                <button class="btn btn-sm btn-outline-danger" title="Deactivate"
                    onclick="confirmDeleteUser(${user.id})"><i class="bi bi-person-x"></i></button>
            </div></td>
        </tr>`).join('') : '<tr><td colspan="7" class="text-center text-muted py-4">No users found.</td></tr>';
    const showMoreButton = document.getElementById('usersShowMoreBtn');
    if (showMoreButton) {
        showMoreButton.classList.toggle('d-none', pageRows.length >= rows.length);
    }
}

async function exportAdminDatabase(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const button = document.getElementById('adminExportButton');
    const status = document.getElementById('adminExportStatus');
    const password = document.getElementById('exportPassword');
    button.disabled = true;
    status.textContent = 'Verifying credentials and preparing the workbook...';
    try {
        const datasets = [...form.querySelectorAll('input[name="datasets"]:checked')]
            .map(input => input.value);
        const response = await fetch('/api/admin/export', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken()
            },
            body: JSON.stringify({
                username: document.getElementById('exportUsername').value.trim(),
                password: password.value,
                datasets
            })
        });
        if (!response.ok) {
            const result = await response.json().catch(() => ({}));
            throw new Error(result.error || `Export failed (${response.status}).`);
        }
        const objectUrl = URL.createObjectURL(await response.blob());
        const link = document.createElement('a');
        link.href = objectUrl;
        link.download = 'devmonitor-database-export.xlsx';
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
        status.textContent = 'Export downloaded successfully.';
        showToast('Database export completed and recorded in the audit log.');
    } catch (error) {
        status.textContent = error.message;
        showToast(error.message, 'danger');
    } finally {
        password.value = '';
        button.disabled = false;
    }
}

function initAdminPage() {
    document.getElementById('adminExportForm')?.addEventListener(
        'submit',
        exportAdminDatabase
    );
    document.getElementById('usersPanel')?.addEventListener('shown.bs.collapse', () => {
        if (!usersLoaded) refreshUsers().catch(error => showToast(error.message, 'danger'));
    });
    for (const kind of ['activity', 'device']) {
        const panel = document.getElementById(`${kind}LogsPanel`);
        panel?.addEventListener('shown.bs.collapse', () => {
            const query = getAdminLogQuery(kind);
            if (!adminLogsLoaded[kind] || adminLogQueries[kind] !== query) {
                refreshAdminLogs(kind).catch(error => showToast(error.message, 'danger'));
            }
        });
        document.getElementById(`${kind}LogsShowMoreBtn`)?.addEventListener('click', () => {
            refreshAdminLogs(kind, { append: true })
                .catch(error => showToast(error.message, 'danger'));
        });
    }
    document.getElementById('userSearchInput')?.addEventListener('input', event => {
        userSearch = event.target.value.trim().toLowerCase();
        userVisibleCount = ITEMS_PER_PAGE;
        renderUsersTable();
    });
    document.getElementById('userSortSelect')?.addEventListener('change', event => {
        userSort = event.target.value;
        renderUsersTable();
    });
    document.getElementById('confirmDeleteUserBtn')?.addEventListener('click', deactivateSelectedUser);
    document.querySelectorAll('.log-search-btn').forEach(button => {
        button.addEventListener('click', () => {
            refreshAdminLogs(button.dataset.logKind)
                .catch(error => showToast(error.message, 'danger'));
        });
    });
    document.querySelectorAll('.log-search-input').forEach(input => {
        input.addEventListener('keydown', event => {
            if (event.key === 'Enter') {
                event.preventDefault();
                const kind = input.id.startsWith('activity') ? 'activity' : 'device';
                refreshAdminLogs(kind).catch(error => showToast(error.message, 'danger'));
            }
        });
        input.addEventListener('input', () => {
            const kind = input.id.startsWith('activity') ? 'activity' : 'device';
            const otherKind = kind === 'activity' ? 'device' : 'activity';
            const otherInput = document.getElementById(`${otherKind}LogSearchInput`);
            if (otherInput) otherInput.value = input.value;
        });
    });
    document.getElementById('usersShowMoreBtn')?.addEventListener('click', () => {
        userVisibleCount += ITEMS_PER_PAGE;
        renderUsersTable();
    });
}

function getAdminLogQuery(kind) {
    return document.getElementById(`${kind}LogSearchInput`)?.value.trim() || '';
}

async function refreshAdminLogs(kind, { append = false } = {}) {
    const body = document.getElementById(`${kind}LogsTableBody`);
    if (!body) return;
    const showMoreButton = document.getElementById(`${kind}LogsShowMoreBtn`);
    if (!append) {
        body.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">Loading logs...</td></tr>';
    }
    const query = getAdminLogQuery(kind);
    const offset = append && adminLogQueries[kind] === query ? adminLogs[kind].length : 0;
    const params = new URLSearchParams({
        kind,
        q: query,
        limit: String(ITEMS_PER_PAGE + 1),
        offset: String(offset)
    });
    if (showMoreButton) showMoreButton.disabled = true;
    try {
        const logs = await api(`/api/admin/logs?${params}`);
        adminLogs[kind] = append && offset
            ? [...adminLogs[kind], ...logs.slice(0, ITEMS_PER_PAGE)]
            : logs.slice(0, ITEMS_PER_PAGE);
        adminLogsHaveMore[kind] = logs.length > ITEMS_PER_PAGE;
        adminLogsLoaded[kind] = true;
        adminLogQueries[kind] = query;
        renderAdminLogs(kind);
    } catch (error) {
        if (!append) {
            body.innerHTML = '<tr><td colspan="6" class="text-center text-danger py-4">Unable to load logs. Try again.</td></tr>';
        }
        throw error;
    } finally {
        if (showMoreButton) showMoreButton.disabled = false;
    }
}

function renderAdminLogs(kind) {
    const body = document.getElementById(`${kind}LogsTableBody`);
    if (!body) return;
    const visibleLogs = adminLogs[kind];
    body.innerHTML = visibleLogs.length ? visibleLogs.map(entry => `
        <tr>
            <td>${escapeHTML(entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '')}</td>
            <td>${escapeHTML(entry.kind === 'activity' ? 'Account activity' : 'Device/system')}</td>
            <td class="fw-semibold">${escapeHTML(entry.event)}</td>
            <td>${escapeHTML(entry.entity || '')}${entry.entity_id ? ` #${escapeHTML(entry.entity_id)}` : ''}</td>
            <td>${escapeHTML(entry.actor)}</td>
            <td>${escapeHTML(entry.details ? JSON.stringify(entry.details) : '')}</td>
        </tr>`).join('') :
        '<tr><td colspan="6" class="text-center text-muted py-4">No matching logs found.</td></tr>';
    const showMoreButton = document.getElementById(`${kind}LogsShowMoreBtn`);
    if (showMoreButton) {
        showMoreButton.classList.toggle('d-none', !adminLogsHaveMore[kind]);
    }
}

function openUserModal(mode, userId) {
    const user = users.find(item => item.id === userId);
    selectedUserId = userId || null;
    document.getElementById('userForm').reset();
    document.getElementById('userFormMode').value = mode;
    document.getElementById('userFormId').value = userId || '';
    document.getElementById('userModalTitle').textContent =
        mode === 'add' ? 'Add User' : 'Edit User';
    document.getElementById('userPasswordGroup').classList.toggle('d-none', mode !== 'add');
    document.getElementById('userConfirmPasswordGroup').classList.toggle('d-none', mode !== 'add');
    document.getElementById('userFormPassword').required = mode === 'add';
    document.getElementById('userFormConfirmPassword').required = mode === 'add';
    document.getElementById('userFormUsername').disabled = mode !== 'add';
    if (user) {
        document.getElementById('userFormFullName').value = user.fullName;
        document.getElementById('userFormUsername').value = user.username;
        document.getElementById('userFormEmail').value = user.email;
        document.getElementById('userFormRole').value = user.role;
        document.getElementById('userFormStatus').value = user.status;
    }
    bootstrap.Modal.getOrCreateInstance(document.getElementById('userModal')).show();
}

async function saveUser() {
    const mode = document.getElementById('userFormMode').value;
    const form = document.getElementById('userForm');
    if (!form.reportValidity()) return;
    const data = {
        full_name: document.getElementById('userFormFullName').value.trim(),
        username: document.getElementById('userFormUsername').value.trim(),
        role: document.getElementById('userFormRole').value,
        status: document.getElementById('userFormStatus').value.toLowerCase()
    };
    const email = document.getElementById('userFormEmail').value.trim();
    if (mode === 'add') {
        data.email = email;
    } else {
        const selectedUser = users.find(item => item.id === selectedUserId);
        if (email && email !== selectedUser?.email && !email.includes('*')) {
            data.email = email;
        }
    }
    if (mode === 'add') {
        data.password = document.getElementById('userFormPassword').value;
        data.confirm_password = document.getElementById('userFormConfirmPassword').value;
        if (data.password !== data.confirm_password) {
            showToast('Passwords do not match.', 'danger');
            return;
        }
    }
    try {
        await api(mode === 'add' ? '/api/users' : `/api/users/${selectedUserId}`, {
            method: mode === 'add' ? 'POST' : 'PATCH',
            body: JSON.stringify(data)
        });
        bootstrap.Modal.getInstance(document.getElementById('userModal')).hide();
        await refreshUsers();
        showToast(mode === 'add' ? 'User account created.' : 'User account updated.');
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

function confirmDeleteUser(userId) {
    selectedUserId = userId;
    const user = users.find(item => item.id === userId);
    document.getElementById('deleteUserName').textContent = user?.fullName || user?.username || '';
    bootstrap.Modal.getOrCreateInstance(document.getElementById('deleteUserModal')).show();
}

async function deactivateSelectedUser() {
    try {
        await api(`/api/users/${selectedUserId}`, { method: 'DELETE' });
        bootstrap.Modal.getInstance(document.getElementById('deleteUserModal')).hide();
        await refreshUsers();
        showToast('User deactivated; associated records were retained.');
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

function initDashboard(notifyOnError = true) {
    const scanCompleted = new URLSearchParams(window.location.search).get('scan');
    if (dashboardRefreshPromise) return dashboardRefreshPromise;
    dashboardRefreshPromise = (async () => {
      try {
        const result = await api('/api/dashboard', { cache: 'no-store' });
        document.getElementById('totalDevices').textContent = result.total;
        document.getElementById('onlineDevices').textContent = result.online;
        document.getElementById('offlineDevices').textContent = result.offline;
        const latestUpdate = result.devices
            .map(device => device.lastUpdated)
            .filter(Boolean)
            .sort()
            .at(-1);
        document.getElementById('lastUpdate').textContent =
            latestUpdate ? new Date(latestUpdate).toLocaleString() : '--';
        const body = document.getElementById('dashboardDeviceTableBody');
        body.innerHTML = result.devices.length ? result.devices.map(device => {
            const color = healthColor(device.healthScore);
            const value = Number.isInteger(device.healthScore)
                ? `${device.healthScore}% · ${healthLabel(device.healthScore)}`
                : healthLabel(null);
            return `<tr><td class="fw-semibold">${escapeHTML(device.name)}</td>
                <td>${escapeHTML(device.owner)}</td><td>${escapeHTML(device.os)}</td>
                <td>${escapeHTML(device.cpu)}</td><td>${escapeHTML(device.ram)}</td>
                <td><a href="/devices/${encodeURIComponent(device.id)}/specifications#health-report"
                    style="color:${color}">
                    ${escapeHTML(value)}
                </a></td>
                <td>${deviceStatusBadge(device.status)}</td></tr>`;
        }).join('') :
            '<tr><td colspan="7" class="text-center text-muted py-4">No registered devices yet.</td></tr>';
        if (scanCompleted === 'complete') {
            showToast('Device scan completed successfully. Dashboard data is up to date.');
            window.history.replaceState({}, '', window.location.pathname);
        }
      } catch (error) {
        if (notifyOnError) showToast(error.message, 'danger');
      }
    })().finally(() => {
        dashboardRefreshPromise = null;
    });
    return dashboardRefreshPromise;
}

document.addEventListener('DOMContentLoaded', () => {
    initSidebar();
    document.getElementById('confirmDeleteDeviceBtn')?.addEventListener('click', archiveSelectedDevice);
    const page = getCurrentPage();
    if (page === 'login') {
        const toggle = document.getElementById('togglePassword');
        const input = document.getElementById('passwordInput');
        toggle?.addEventListener('click', () => {
            const showPassword = input.type === 'password';
            input.type = showPassword ? 'text' : 'password';
            toggle.querySelector('i').className = showPassword ? 'bi bi-eye-slash' : 'bi bi-eye';
        });
    }
    if (page === 'dashboard') {
        initDashboard();
        window.setInterval(() => {
            if (!document.hidden) initDashboard(false);
        }, 10000);
    }
    if (page === 'devices') initDevicesPage();
    if (page === 'device-verification') initDeviceVerificationPage();
    if (page === 'archived-devices') initArchivedDevicesPage();
    if (page === 'admin') initAdminPage();
});
