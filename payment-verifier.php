<?php
/**
 * Plugin Name: Payment Verifier
 * Description: Android SMS payment verification API and WooCommerce payment matching foundation.
 * Version: 3.2.0
 * Requires Plugins: woocommerce
 */

if (!defined('ABSPATH')) {
    exit;
}

error_log('PV DEBUG: payment-verifier.php loaded');

/*
 * Core includes
 */
require_once plugin_dir_path(__FILE__) . 'includes/pv-order-transition-guard.php';
require_once plugin_dir_path(__FILE__) . 'includes/pv-integrity-check.php';
require_once plugin_dir_path(__FILE__) . 'includes/pv-api-hardening.php';

error_log('PV BEFORE PAYMENT-SMS REGISTRATION');

define('PV_VERSION', '3.2.0');
define('PV_DB_VERSION', '3');

register_activation_hook(__FILE__, 'pv_activate');
add_action('plugins_loaded', function(){
    if (get_option('pv_db_version') !== PV_DB_VERSION) {
        pv_activate();
    }
}, 1);

function pv_activate() {
    global $wpdb;

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';

    $charset = $wpdb->get_charset_collate();
    $payments = $wpdb->prefix . 'pv_payments';
    $devices  = $wpdb->prefix . 'pv_devices';
    $logs     = $wpdb->prefix . 'pv_audit_logs';

    dbDelta("CREATE TABLE $payments (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        order_id BIGINT UNSIGNED NOT NULL,
        provider VARCHAR(30) NOT NULL,
        amount DECIMAL(18,2) NOT NULL,
        transaction_id VARCHAR(80) NOT NULL,
        device_id VARCHAR(100) NOT NULL,
        status VARCHAR(30) NOT NULL DEFAULT 'pending',
        verified_at DATETIME NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY transaction_id (transaction_id),
        KEY order_id (order_id),
        KEY status (status)
    ) $charset;");

    dbDelta("CREATE TABLE $devices (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        device_id VARCHAR(100) NOT NULL,
        api_key_hash CHAR(64) NOT NULL,
        public_key LONGTEXT NULL,
        active TINYINT(1) NOT NULL DEFAULT 1,
        last_seen DATETIME NULL,
        created_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY device_id (device_id)
    ) $charset;");

    dbDelta("CREATE TABLE $logs (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        event_type VARCHAR(80) NOT NULL,
        order_id BIGINT UNSIGNED NULL,
        transaction_id VARCHAR(80) NULL,
        device_id VARCHAR(100) NULL,
        message TEXT NULL,
        created_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        KEY event_type (event_type),
        KEY order_id (order_id),
        KEY transaction_id (transaction_id)
    ) $charset;");

    $requests = $wpdb->prefix . 'pv_verification_requests';
    dbDelta("CREATE TABLE $requests (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        request_id CHAR(36) NOT NULL,
        device_id VARCHAR(100) NULL,
        phone VARCHAR(32) NOT NULL,
        phone_hash CHAR(64) NOT NULL,
        transaction_hash CHAR(64) NOT NULL,
        transaction_value VARCHAR(191) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'pending',
        reason_code VARCHAR(50) NULL,
        created_at DATETIME NOT NULL,
        expires_at DATETIME NOT NULL,
        completed_at DATETIME NULL,
        PRIMARY KEY (id),
        UNIQUE KEY request_id (request_id),
        KEY status (status),
        KEY phone_hash (phone_hash),
        KEY expires_at (expires_at)
    ) $charset;");

    update_option('pv_db_version', PV_DB_VERSION);
}

function pv_request_id() {
    return wp_generate_uuid4();
}

function pv_log($event, $message = '', $order_id = null, $transaction_id = null, $device_id = null) {
    // Compatibility wrapper: all operational events now flow into the Phase 22
    // audit table so the admin audit viewer has one authoritative event stream.
    $outcome = (strpos((string) $event, 'rejected') === 0 ||
        strpos((string) $event, 'mismatch') !== false ||
        strpos((string) $event, 'duplicate') !== false ||
        strpos((string) $event, 'violation') !== false ||
        strpos((string) $event, 'concurrent') !== false) ? 'rejected' : 'info';

    pv_audit(array(
        'correlation_id' => pv_correlation_id(),
        'event_type' => $event,
        'outcome' => $outcome,
        'device_id' => $device_id ?: '',
        'order_id' => $order_id,
        'transaction_id' => $transaction_id ?: '',
        'message' => is_scalar($message) ? (string) $message : wp_json_encode($message),
    ));
}

function pv_authenticate_device(WP_REST_Request $request) {
    $header = $request->get_header('authorization');

    if (!preg_match('/^Bearer\s+(.+)$/i', trim($header), $m)) {
        return new WP_Error('pv_unauthorized', 'Missing device token.', array('status' => 401));
    }

    $raw_key = trim($m[1]);
    $claimed_device_id = sanitize_text_field($request->get_header('x-pv-device-id'));
    if ($claimed_device_id === '') {
        return new WP_Error('pv_missing_device_id', 'X-PV-Device-ID header is required.', array('status' => 400));
    }
    global $wpdb;

    $hash = hash('sha256', $raw_key);
    $device = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}pv_devices
         WHERE api_key_hash = %s AND device_id = %s AND active = 1 LIMIT 1",
        $hash, $claimed_device_id
    ));

    if (!$device) {
        return new WP_Error('pv_unauthorized', 'Invalid or inactive device token.', array('status' => 401));
    }

    $wpdb->update(
        $wpdb->prefix . 'pv_devices',
        array('last_seen' => current_time('mysql', true)),
        array('id' => $device->id),
        array('%s'),
        array('%d')
    );

    return $device;
}



/* =========================
 * Phase 20 — Verification Hardening
 * ========================= */

add_action('init', 'pv_hardening_schema_migration', 20);

function pv_hardening_schema_migration() {
    if ((string) get_option('pv_hardening_db_version') === '1') return;

    global $wpdb;
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    $charset = $wpdb->get_charset_collate();
    $idempotency = $wpdb->prefix . 'pv_idempotency';

    dbDelta("CREATE TABLE $idempotency (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        idempotency_key VARCHAR(191) NOT NULL,
        device_id VARCHAR(100) NOT NULL,
        request_hash CHAR(64) NOT NULL,
        response_code SMALLINT UNSIGNED NOT NULL DEFAULT 200,
        response_body LONGTEXT NULL,
        created_at DATETIME NOT NULL,
        expires_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY idempotency_key (idempotency_key),
        KEY device_id (device_id),
        KEY expires_at (expires_at)
    ) $charset;");

    update_option('pv_hardening_db_version', '1');
}

function pv_idempotency_key(WP_REST_Request $request) {
    $key = trim((string) $request->get_header('idempotency-key'));
    if ($key === '') {
        $key = trim((string) $request->get_header('x-pv-idempotency-key'));
    }
    return $key;
}

function pv_request_fingerprint($data) {
    return hash('sha256', wp_json_encode($data));
}

function pv_load_idempotent_response($key, $device_id, $request_hash) {
    if (!$key) return null;

    global $wpdb;
    $row = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}pv_idempotency
         WHERE idempotency_key=%s AND device_id=%s AND expires_at > %s
         LIMIT 1",
        $key, $device_id, current_time('mysql', true)
    ));

    if (!$row) return null;

    if (!hash_equals($row->request_hash, $request_hash)) {
        return new WP_Error(
            'pv_idempotency_conflict',
            'Idempotency key was already used with a different request.',
            array('status' => 409)
        );
    }

    $body = json_decode($row->response_body, true);
    return new WP_REST_Response(
        is_array($body) ? $body : array('success' => false, 'status' => 'replayed'),
        (int) $row->response_code
    );
}

function pv_store_idempotent_response($key, $device_id, $request_hash, $response) {
    if (!$key || !($response instanceof WP_REST_Response)) return;

    global $wpdb;
    $now = current_time('mysql', true);
    $expires = gmdate('Y-m-d H:i:s', time() + DAY_IN_SECONDS);

    $wpdb->query($wpdb->prepare(
        "INSERT IGNORE INTO {$wpdb->prefix}pv_idempotency
        (idempotency_key, device_id, request_hash, response_code, response_body, created_at, expires_at)
        VALUES (%s,%s,%s,%d,%s,%s,%s)",
        $key,
        $device_id,
        $request_hash,
        (int) $response->get_status(),
        wp_json_encode($response->get_data()),
        $now,
        $expires
    ));
}

function pv_verification_rate_limit($device_id) {
    $key = 'pv_rl_' . hash('sha256', $device_id);
    $count = (int) get_transient($key);

    if ($count >= 60) {
        return new WP_Error(
            'pv_rate_limited',
            'Too many verification requests. Please retry later.',
            array('status' => 429, 'retry_after' => 60)
        );
    }

    set_transient($key, $count + 1, MINUTE_IN_SECONDS);
    return true;
}

function pv_normalize_transaction_id($txn) {
    return strtoupper(preg_replace('/[^A-Z0-9_-]/i', '', trim((string) $txn)));
}

function pv_money_equal($a, $b) {
    return abs(round((float) $a, 2) - round((float) $b, 2)) < 0.005;
}

function pv_require_https(WP_REST_Request $request) {
    if (!is_ssl() && !defined('PV_ALLOW_INSECURE_LOCAL') ) {
        return new WP_Error(
            'pv_https_required',
            'HTTPS is required for Payment Verifier API requests.',
            array('status' => 403)
        );
    }
    return true;
}

function pv_rest_permission(WP_REST_Request $request) {
    $device = pv_authenticate_device($request);
    if (is_wp_error($device)) {
        return $device;
    }
    $request->set_param('_pv_authenticated_device', $device);
    return true;
}

function pv_receive_payment_sms(WP_REST_Request $request) {
    global $wpdb;

    $request_id = pv_request_id();
    $device = $request->get_param('_pv_authenticated_device');

    if (!$device || !is_object($device)) {
        return new WP_Error('pv_unauthorized', 'Device authentication failed.', array('status' => 401));
    }

    $data = $request->get_json_params();
    if (!is_array($data)) {
        $data = $request->get_body_params();
    }
    if (!is_array($data)) {
        return new WP_Error('pv_invalid_request', 'A valid payment request is required.', array('status' => 400));
    }

    $reference = sanitize_text_field($data['reference'] ?? '');

    $provider = sanitize_key($data['provider'] ?? '');

    $amount = isset($data['amount'])
        ? (float) $data['amount']
        : 0;

    $txn = pv_normalize_transaction_id(
        $data['transaction_id'] ?? ''
    );

    $device_id = sanitize_text_field(
        $data['device_id'] ?? ''
    );

    if (!$reference) {
        return new WP_Error(
            'pv_missing_reference',
            'Payment reference is required.',
            array('status' => 400)
        );
    }

    $key = pv_idempotency_key($request);

    if (!$key || strlen($key) < 16 || strlen($key) > 191) {
        return new WP_Error(
            'pv_missing_idempotency_key',
            'A valid Idempotency-Key header is required.',
            array('status' => 428)
        );
    }

    $orders = wc_get_orders(array(
        'limit' => 2,
        'meta_key' => '_pv_payment_reference',
        'meta_value' => $reference,
        'return' => 'objects',
    ));

    if (empty($orders)) {
        pv_log('rejected_order', 'WooCommerce order not found.', null, $txn, $device->device_id);
        return new WP_Error('pv_reference_not_found', 'Payment reference does not match any order.', array('status' => 404));
    }

    if (count($orders) !== 1) {
        pv_log('reference_integrity_violation', 'Payment reference matches multiple orders.', null, $txn, $device->device_id);
        return new WP_Error('pv_reference_not_unique', 'Payment reference is not unique.', array('status' => 500));
    }

    $matched = $orders[0];
    $order_id = $matched->get_id();

    error_log('PV VERIFY DEBUG: ' . wp_json_encode(array(
        'reference' => $reference,
        'provider' => $provider,
        'amount' => round($amount, 2),
        'transaction_id' => $txn,
        'device_id' => $device_id,
        'resolved_order_id' => (int) $order_id,
        'validation_result' => 'order_resolved',
    )));

    $request_hash = pv_request_fingerprint(array(
        'reference' => $reference,
        'provider' => $provider,
        'amount' => round($amount, 2),
        'transaction_id' => $txn,
        'device_id' => $device_id,
    ));

    $replay = pv_load_idempotent_response($key, $device->device_id, $request_hash);
    if ($replay instanceof WP_Error || $replay instanceof WP_REST_Response) {
        pv_log('idempotency_replay', 'Returning previously stored response.', $order_id, $txn, $device->device_id);
        return $replay;
    }

    if (!in_array($provider, array('bkash', 'nagad'), true)) {
        pv_log('rejected_provider', 'Unsupported provider.', $order_id, $txn, $device->device_id);
        return new WP_Error('pv_invalid_provider', 'Unsupported provider.', array('status' => 422));
    }

    if ($amount <= 0 || $amount > 10000000) {
        pv_log('rejected_amount', 'Invalid amount.', $order_id, $txn, $device->device_id);
        return new WP_Error('pv_invalid_amount', 'Invalid amount.', array('status' => 422));
    }

    if ($device_id !== $device->device_id) {
        pv_log('rejected_device', 'Device ID mismatch.', $order_id, $txn, $device->device_id);
        return new WP_Error('pv_device_mismatch', 'Device ID mismatch.', array('status' => 403));
    }

    $store = pv_get_device_store($device);
    if (!$store) {
        return new WP_Error('pv_device_unassigned', 'Device has no active store assignment.', array('status' => 403));
    }

    if ($txn === '') {
        return new WP_Error('pv_missing_txn', 'Transaction ID is required.', array('status' => 422));
    }

    /*
     * Store boundary: this WordPress installation is represented by the
     * active store assignment. Future multi-tenant deployments should attach
     * an explicit tenant ID to each order and enforce it here.
     */
    $order_store_key = sanitize_key($matched->get_meta('_pv_store_key'));
    if ($order_store_key && $order_store_key !== $store->store_key) {
        pv_log('store_scope_violation', 'Order belongs to a different store scope.', $order_id, $txn, $device->device_id);
        return new WP_Error('pv_store_scope_violation', 'Order is outside this device store scope.', array('status' => 403));
    }

    $expected_provider = sanitize_key($matched->get_meta('_pv_provider'));
    $expected_txn = pv_normalize_transaction_id($matched->get_meta('_pv_transaction_id'));
    $expected_amount = (float) $matched->get_total();

    if ($expected_provider && $expected_provider !== $provider) {
        pv_log('binding_mismatch', 'Payment provider does not match order binding.', $order_id, $txn, $device->device_id);
        return new WP_Error('pv_provider_mismatch', 'Payment provider does not match the order.', array('status' => 409));
    }

    if ($expected_txn && !hash_equals($expected_txn, $txn)) {
        pv_log('binding_mismatch', 'Transaction ID does not match order binding.', $order_id, $txn, $device->device_id);
        return new WP_Error('pv_transaction_mismatch', 'Transaction ID does not match the order.', array('status' => 409));
    }

    if (!pv_money_equal($expected_amount, $amount)) {
        pv_log('binding_mismatch', 'Payment amount does not match order total.', $order_id, $txn, $device->device_id);
        return new WP_Error('pv_order_amount_mismatch', 'Payment amount does not match the order total.', array('status' => 409));
    }

    if ($matched->get_meta('_pv_verification_status') === 'verified') {
        $body = array(
            'success' => true,
            'status' => 'already_verified',
            'request_id' => $request_id,
            'order_id' => $order_id,
            'transaction_id' => $txn,
        );
        $response = new WP_REST_Response($body, 200);
        pv_store_idempotent_response($key, $device->device_id, $request_hash, $response);
        return $response;
    }

    if (!in_array($matched->get_status(), array('pending', 'on-hold'), true)) {
        pv_log('rejected_order_status', 'Order is not awaiting payment verification.', $order_id, $txn, $device->device_id);
        return new WP_Error('pv_invalid_order_status', 'Order is not awaiting payment verification.', array('status' => 409));
    }

    $existing = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}pv_payments WHERE transaction_id = %s LIMIT 1",
        $txn
    ));

    if ($existing) {
        if ((int) $existing->order_id === $order_id && $existing->status === 'verified') {
            $body = array(
                'success' => true,
                'status' => 'already_verified',
                'request_id' => $request_id,
                'order_id' => $order_id,
                'transaction_id' => $txn,
            );
            $response = new WP_REST_Response($body, 200);
            pv_store_idempotent_response($key, $device->device_id, $request_hash, $response);
            return $response;
        }

        pv_log('duplicate_transaction', 'Transaction ID already belongs to another payment event.', $existing->order_id, $txn, $device->device_id);
        return new WP_Error('pv_duplicate', 'Transaction ID already exists.', array('status' => 409));
    }

    $now = current_time('mysql', true);

    /*
     * UNIQUE(transaction_id) is the database-level replay/concurrency guard.
     * If two requests race, exactly one INSERT can win.
     */
    $inserted = $wpdb->insert(
        $wpdb->prefix . 'pv_payments',
        array(
            'order_id' => $order_id,
            'provider' => $provider,
            'amount' => round($amount, 2),
            'transaction_id' => $txn,
            'device_id' => $device_id,
            'status' => 'verified',
            'verified_at' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ),
        array('%d','%s','%f','%s','%s','%s','%s','%s','%s')
    );

    if (!$inserted) {
        $race = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}pv_payments WHERE transaction_id = %s LIMIT 1",
            $txn
        ));
        pv_log('concurrent_duplicate', 'Database uniqueness prevented duplicate verification.', $race ? $race->order_id : $order_id, $txn, $device->device_id);
        return new WP_Error('pv_duplicate', 'Transaction ID already exists.', array('status' => 409));
    }

    $matched->update_meta_data('_pv_verification_status', 'verified');
    $matched->update_meta_data('_pv_transaction_id', $txn);
    $matched->update_meta_data('_pv_verified', 'yes');
    $matched->update_meta_data('_pv_verified_transaction_id', $txn);
    $matched->update_meta_data('_pv_verified_provider', $provider);
    $matched->save();

    $matched->payment_complete($txn);
    $matched->add_order_note(
        sprintf(
            'Payment verified by Payment Verifier. Provider: %s. Transaction ID: %s. Amount: %s.',
            strtoupper($provider),
            $txn,
            wc_price($amount)
        )
    );

    pv_log(
        'payment_verified',
        array(
            'message' => 'Payment matched and completed.',
            'request_id' => $request_id,
            'store_id' => (int) $store->id,
        ),
        $order_id,
        $txn,
        $device->device_id
    );

    error_log('PV VERIFY DEBUG: ' . wp_json_encode(array(
        'reference' => $reference,
        'provider' => $provider,
        'amount' => round($amount, 2),
        'transaction_id' => $txn,
        'device_id' => $device_id,
        'resolved_order_id' => (int) $order_id,
        'validation_result' => 'verified',
    )));

    $body = array(
        'success' => true,
        'status' => 'verified',
        'request_id' => $request_id,
        'order_id' => $order_id,
        'transaction_id' => $txn,
    );

    $response = new WP_REST_Response($body, 200);
    pv_store_idempotent_response($key, $device->device_id, $request_hash, $response);
    return $response;
}

/* =========================
 * Phase 8 — Admin Dashboard
 * ========================= */
add_action('admin_menu', function () {
    add_menu_page('Payment Verifier','Payment Verifier','manage_woocommerce','payment-verifier','pv_admin_dashboard','dashicons-shield',56);
    add_submenu_page('payment-verifier','Devices','Devices','manage_woocommerce','payment-verifier-devices','pv_admin_devices');
    add_submenu_page('payment-verifier','Payments','Payments','manage_woocommerce','payment-verifier-payments','pv_admin_payments');
    add_submenu_page('payment-verifier','Audit Logs','Audit Logs','manage_woocommerce','payment-verifier-logs','pv_admin_logs');
});

function pv_admin_guard() {
    if (!current_user_can('manage_woocommerce')) wp_die('You do not have permission to access Payment Verifier.');
}

function pv_stat_card($label, $value) {
    echo '<div style="background:#fff;padding:20px;border:1px solid #ddd;border-radius:8px"><div style="color:#666">'.esc_html($label).'</div><strong style="font-size:30px">'.esc_html($value).'</strong></div>';
}

function pv_admin_dashboard() {
    pv_admin_guard(); global $wpdb;
    $p=$wpdb->prefix.'pv_payments'; $d=$wpdb->prefix.'pv_devices';
    $verified=(int)$wpdb->get_var("SELECT COUNT(*) FROM $p WHERE status='verified'");
    $unmatched=(int)$wpdb->get_var("SELECT COUNT(*) FROM $p WHERE status='unmatched'");
    $devices=(int)$wpdb->get_var("SELECT COUNT(*) FROM $d WHERE active=1");
    $total=(int)$wpdb->get_var("SELECT COUNT(*) FROM $p");
    ?>
    <div class="wrap"><h1>Payment Verifier</h1>
    <p>Payment verification control center.</p>
    <div style="display:grid;grid-template-columns:repeat(4,minmax(160px,1fr));gap:16px;max-width:1000px">
    <?php pv_stat_card('Verified Payments',$verified); pv_stat_card('Unmatched Payments',$unmatched); pv_stat_card('Active Devices',$devices); pv_stat_card('Total Events',$total); ?>
    </div>
    <p style="margin-top:20px">
      <a class="button button-primary" href="<?php echo esc_url(admin_url('admin.php?page=payment-verifier-devices')); ?>">Manage Devices</a>
      <a class="button" href="<?php echo esc_url(admin_url('admin.php?page=payment-verifier-payments')); ?>">View Payments</a>
      <a class="button" href="<?php echo esc_url(admin_url('admin.php?page=payment-verifier-logs')); ?>">Audit Logs</a>
    </p>
    <table class="widefat striped" style="max-width:1000px;margin-top:25px"><tbody>
      <tr><td>Device authentication</td><td>Bearer API key</td></tr>
      <tr><td>Duplicate protection</td><td>Enabled</td></tr>
      <tr><td>Audit logging</td><td>Enabled</td></tr>
      <tr><td>HTTPS</td><td><?php echo is_ssl()?'<strong style="color:green">Detected</strong>':'<strong style="color:#b32d2e">Not detected</strong>'; ?></td></tr>
    </tbody></table></div>
    <?php
}

function pv_admin_devices() {
    pv_admin_guard(); global $wpdb; $t=$wpdb->prefix.'pv_devices';

    if (isset($_POST['pv_create_device'])) {
        check_admin_referer('pv_create_device');
        $device_id=sanitize_text_field(wp_unslash($_POST['device_id']??''));
        if (!$device_id) {
            echo '<div class="notice notice-error"><p>Device ID is required.</p></div>';
        } elseif ($wpdb->get_var($wpdb->prepare("SELECT id FROM $t WHERE device_id=%s",$device_id))) {
            echo '<div class="notice notice-error"><p>Device ID already exists.</p></div>';
        } else {
            $key=wp_generate_password(48,false,false);
            $wpdb->insert($t,array('device_id'=>$device_id,'api_key_hash'=>hash('sha256',$key),'active'=>1,'created_at'=>current_time('mysql',true)),array('%s','%s','%d','%s'));
            echo '<div class="notice notice-success"><p>Device created. Copy this API key now; it will not be shown again.</p></div>';
            echo '<div style="background:#fff;border:1px solid #ccd0d4;padding:15px;max-width:700px"><code style="word-break:break-all">'.esc_html($key).'</code></div>';
        }
    }

    if (isset($_GET['pv_toggle_device'])) {
        $id=absint($_GET['pv_toggle_device']); check_admin_referer('pv_toggle_device_'.$id);
        $active=$wpdb->get_var($wpdb->prepare("SELECT active FROM $t WHERE id=%d",$id));
        if ($active!==null) $wpdb->update($t,array('active'=>((int)$active?0:1)),array('id'=>$id),array('%d'),array('%d'));
        wp_safe_redirect(admin_url('admin.php?page=payment-verifier-devices')); exit;
    }

    $rows=$wpdb->get_results("SELECT * FROM $t ORDER BY id DESC");
    ?>
    <div class="wrap"><h1>Payment Verifier — Devices</h1>
    <form method="post" style="background:#fff;border:1px solid #ddd;padding:18px;max-width:700px;margin-bottom:25px">
      <?php wp_nonce_field('pv_create_device'); ?><input type="hidden" name="pv_create_device" value="1">
      <h2>Register Android Device</h2>
      <input class="regular-text" name="device_id" placeholder="STORE-DEVICE-01" required>
      <button class="button button-primary" type="submit">Generate Device API Key</button>
    </form>
    <table class="widefat striped"><thead><tr><th>Device ID</th><th>Status</th><th>Last Seen</th><th>Created</th><th>Action</th></tr></thead><tbody>
    <?php if(!$rows): ?><tr><td colspan="5">No devices registered.</td></tr><?php else: foreach($rows as $r):
      $url=wp_nonce_url(admin_url('admin.php?page=payment-verifier-devices&pv_toggle_device='.(int)$r->id),'pv_toggle_device_'.(int)$r->id); ?>
      <tr><td><strong><?php echo esc_html($r->device_id); ?></strong></td><td><?php echo $r->active?'<span style="color:green">Active</span>':'<span style="color:#b32d2e">Revoked</span>'; ?></td><td><?php echo esc_html($r->last_seen?:'Never'); ?></td><td><?php echo esc_html($r->created_at); ?></td><td><a class="button" href="<?php echo esc_url($url); ?>"><?php echo $r->active?'Revoke':'Activate'; ?></a></td></tr>
    <?php endforeach; endif; ?></tbody></table></div>
    <?php
}

function pv_admin_payments() {
    pv_admin_guard(); global $wpdb; $t=$wpdb->prefix.'pv_payments';
    $rows=$wpdb->get_results("SELECT * FROM $t ORDER BY id DESC LIMIT 200");
    ?>
    <div class="wrap"><h1>Payment Verification History</h1>
    <table class="widefat striped"><thead><tr><th>ID</th><th>Order</th><th>Provider</th><th>Amount</th><th>Transaction ID</th><th>Device</th><th>Status</th><th>Verified</th></tr></thead><tbody>
    <?php if(!$rows): ?><tr><td colspan="8">No payment events.</td></tr><?php else: foreach($rows as $r): ?>
      <tr><td><?php echo (int)$r->id; ?></td><td><?php echo $r->order_id?'<a href="'.esc_url(get_edit_post_link($r->order_id)).'">#'.(int)$r->order_id.'</a>':'—'; ?></td><td><?php echo esc_html(strtoupper($r->provider)); ?></td><td><?php echo esc_html(number_format((float)$r->amount,2)); ?></td><td><code><?php echo esc_html($r->transaction_id); ?></code></td><td><?php echo esc_html($r->device_id); ?></td><td><strong><?php echo esc_html(strtoupper($r->status)); ?></strong></td><td><?php echo esc_html($r->verified_at?:'—'); ?></td></tr>
    <?php endforeach; endif; ?></tbody></table></div>
    <?php
}

function pv_admin_logs() {
    pv_admin_guard(); global $wpdb; $t=$wpdb->prefix.'pv_audit_logs';
    $rows=$wpdb->get_results("SELECT * FROM $t ORDER BY id DESC LIMIT 300");
    ?>
    <div class="wrap"><h1>Payment Verifier — Audit Logs</h1>
    <table class="widefat striped"><thead><tr><th>Time</th><th>Event</th><th>Order</th><th>Transaction</th><th>Device</th><th>Message</th></tr></thead><tbody>
    <?php if(!$rows): ?><tr><td colspan="6">No audit events.</td></tr><?php else: foreach($rows as $r): ?>
      <tr><td><?php echo esc_html($r->created_at); ?></td><td><strong><?php echo esc_html($r->event_type); ?></strong></td><td><?php echo $r->order_id?'#'.(int)$r->order_id:'—'; ?></td><td><?php echo $r->transaction_id?'<code>'.esc_html($r->transaction_id).'</code>':'—'; ?></td><td><?php echo esc_html($r->device_id?:'—'); ?></td><td><?php echo esc_html($r->message); ?></td></tr>
    <?php endforeach; endif; ?></tbody></table></div>
    <?php
}

add_action('woocommerce_admin_order_data_after_order_details', function($order) {
    if (!current_user_can('manage_woocommerce')) return;
    echo '<div class="order_data_column" style="margin-top:20px"><h4>Payment Verifier</h4>';
    if ($order->get_meta('_pv_verified')==='yes') {
        echo '<p><strong style="color:green">Verified</strong></p>';
        echo '<p>Provider: '.esc_html(strtoupper($order->get_meta('_pv_verified_provider'))).'</p>';
        echo '<p>Transaction ID: <code>'.esc_html($order->get_meta('_pv_verified_transaction_id')).'</code></p>';
    } else echo '<p><strong style="color:#996800">Not verified by Payment Verifier</strong></p>';
    echo '</div>';
});


require_once __DIR__ . '/includes/class-wc-gateway-payment-verifier.php';

/**
 * Add payment instructions immediately after the
 * "Thank you. Your order has been received." message.
 */
add_filter(
    'woocommerce_thankyou_order_received_text',
    'pv_add_payment_instructions_to_thankyou',
    20,
    2
);

function pv_add_payment_instructions_to_thankyou($message, $order) {

    if (!$order instanceof WC_Order) {
        return $message;
    }

    $reference = sanitize_text_field(
        $order->get_meta('_pv_payment_reference')
    );

    if (!$reference) {
        return $message;
    }

    $instructions = '
        <div style="
            margin: 20px 0;
            padding: 18px;
            border: 1px solid #ddd;
            border-radius: 6px;
            background: #fafafa;
        ">

            <h3 style="
                margin: 0 0 12px;
                font-size: 28px;
                font-weight: bold;
            ">
                Complete Payment to Confirm Your Order
            </h3>

            <p style="margin: 7px 0;">
                <strong>Payment Reference:</strong>
                <code style="
                    font-size: 16px;
                    font-weight: 600;
                    padding: 3px 6px;
                    background: #eee;
                    border-radius: 3px;
                ">' . esc_html($reference) . '</code>
            </p>

            <p style="margin: 7px 0;">
                Enter this reference in the
                <strong>Reference</strong> field when making your payment.
            </p>
        </div>
    ';

    return $message . $instructions;
}


/* =========================
 * Phase 14 — Android Order Sync
 * ========================= */

add_action('rest_api_init', function () {
    register_rest_route('payment-verifier/v1', '/orders', array(
        'methods' => WP_REST_Server::READABLE,
        'callback' => 'pv_sync_orders',
        'permission_callback' => 'pv_scoped_device_permission',
        'args' => array(
            'since' => array(
                'required' => false,
                'type' => 'integer',
                'default' => 0,
            ),
            'limit' => array(
                'required' => false,
                'type' => 'integer',
                'default' => 100,
            ),
        ),
    ));
});

function pv_sync_orders(WP_REST_Request $request) {
    $device = pv_device_from_request($request);

    if (is_wp_error($device)) {
        return $device;
    }

    $store = pv_get_device_store($device);

    if (!$store) {
        return new WP_Error(
            'pv_device_unassigned',
            'Device has no active store assignment.',
            array('status' => 403)
        );
    }

    $since = max(
        0,
        absint($request->get_param('since'))
    );

    $limit = min(
        200,
        max(1, absint($request->get_param('limit')))
    );

    $orders = wc_get_orders(array(
        'status' => array('pending', 'on-hold'),
        'limit' => $limit,
        'orderby' => 'date',
        'order' => 'ASC',
        'return' => 'objects',
        'date_created' => $since
            ? '>' . gmdate('Y-m-d H:i:s', $since)
            : '',
    ));

    $items = array();

    foreach ($orders as $order) {

        $provider = sanitize_key(
            $order->get_meta('_pv_provider')
        );

        /*
         * Only Payment Verifier orders.
         */
        if (!in_array($provider, array('bkash', 'nagad'), true)) {
            continue;
        }

        /*
         * Store scope.
         */
        $order_store_key = sanitize_key(
            $order->get_meta('_pv_store_key')
        );

        if (
            $order_store_key &&
            $order_store_key !== $store->store_key
        ) {
            continue;
        }

        $transaction_id = sanitize_text_field(
            $order->get_meta('_pv_transaction_id')
        );

        $payment_reference = sanitize_text_field(
            $order->get_meta('_pv_payment_reference')
        );

        $verification_status = sanitize_key(
            $order->get_meta('_pv_verification_status')
        );

        /*
         * Don't send already verified orders to Android.
         */
        if ($verification_status === 'verified') {
            continue;
        }

        $items[] = array(
            'order_id' => (int) $order->get_id(),

            'provider' => $provider,

            'amount' => (float) $order->get_total(),

            /*
             * Empty until Android finds the real SMS transaction.
             */
            'transaction_id' => $transaction_id,

            /*
             * Reference generated when checkout was completed.
             */
            'payment_reference' => $payment_reference,

            'status' => $order->get_status(),

            'verification_status' => $verification_status ?: 'pending',

            'created_at' => $order->get_date_created()
                ? $order->get_date_created()->getTimestamp()
                : 0,

            'updated_at' => $order->get_date_modified()
                ? $order->get_date_modified()->getTimestamp()
                : 0,
        );
    }

    return new WP_REST_Response(
        array(
            'success' => true,
            'server_time' => time(),
            'store_id' => (int) $store->id,
            'store_key' => $store->store_key,
            'items' => $items,
        ),
        200
    );
}


/* =========================
 * Phase 15 — Device Provisioning & Store Scoping
 * ========================= */

function pv_device_table() {
    global $wpdb;
    return $wpdb->prefix . 'pv_devices';
}

register_activation_hook(__FILE__, 'pv_create_device_table');

function pv_create_device_table() {
    global $wpdb;
    $table = pv_device_table();
    $charset = $wpdb->get_charset_collate();

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta("CREATE TABLE {$table} (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        device_id VARCHAR(128) NOT NULL,
        device_name VARCHAR(191) NOT NULL DEFAULT '',
        api_key_hash CHAR(64) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'active',
        created_at DATETIME NOT NULL,
        last_seen_at DATETIME NULL,
        PRIMARY KEY (id),
        UNIQUE KEY device_id (device_id),
        KEY status (status)
    ) {$charset};");
}

function pv_device_from_request(WP_REST_Request $request) {

    error_log(
        'PV AUTH DEBUG: ' .
        wp_json_encode(array(
            'x_pv_device_id' => $request->get_header('x-pv-device-id'),
        ))
    );

    global $wpdb;

    $auth = $request->get_header('authorization');

    if (
        !$auth ||
        !preg_match('/^Bearer\s+(.+)$/i', trim($auth), $m)
    ) {
        return new WP_Error(
            'pv_missing_auth',
            'Missing device authorization.',
            array(
                'status' => 401,
            )
        );
    }

    $key = trim($m[1]);
    $hash = hash('sha256', $key);

    $device_id = sanitize_text_field(
        $request->get_header('x-pv-device-id')
    );

    error_log(
        'PV AUTH HASH: ' . $hash .
        ' DEVICE: ' . $device_id
    );

    $row = $wpdb->get_row(
        $wpdb->prepare(
            "SELECT *
             FROM " . pv_device_table() . "
             WHERE api_key_hash = %s
             AND status = 'active'
             LIMIT 1",
            $hash
        )
    );

    if (!$row) {
        return new WP_Error(
            'pv_invalid_device',
            'Invalid or revoked device credential.',
            array(
                'status' => 401,
            )
        );
    }

    if (
        $device_id &&
        !hash_equals(
            (string) $row->device_id,
            $device_id
        )
    ) {
        return new WP_Error(
            'pv_device_mismatch',
            'Device ID does not match credential.',
            array(
                'status' => 403,
            )
        );
    }

    $wpdb->update(
        pv_device_table(),
        array(
            'last_seen_at' => current_time('mysql', true),
        ),
        array(
            'id' => $row->id,
        ),
        array('%s'),
        array('%d')
    );

    return $row;
}


function pv_device_permission(WP_REST_Request $request) {
    $https = pv_require_https($request);
    if (is_wp_error($https)) return $https;
    return pv_device_from_request($request);
}

add_action('rest_api_init', function () {
    register_rest_route('payment-verifier/v1', '/device/heartbeat', array(
        'methods' => WP_REST_Server::CREATABLE,
        'callback' => 'pv_device_heartbeat',
        'permission_callback' => 'pv_device_permission',
    ));

    register_rest_route('payment-verifier/v1', '/device/revoke', array(
        'methods' => WP_REST_Server::CREATABLE,
        'callback' => 'pv_device_revoke_self',
        'permission_callback' => 'pv_device_permission',
    ));
});

function pv_device_heartbeat(WP_REST_Request $request) {
    $device = pv_device_from_request($request);
    if (is_wp_error($device)) return $device;

    return new WP_REST_Response(array(
        'success' => true,
        'device_id' => $device->device_id,
        'status' => $device->status,
        'server_time' => time(),
    ), 200);
}

function pv_device_revoke_self(WP_REST_Request $request) {
    global $wpdb;
    $device = pv_device_from_request($request);
    if (is_wp_error($device)) return $device;

    $wpdb->update(
        pv_device_table(),
        array('status' => 'revoked'),
        array('id' => $device->id),
        array('%s'),
        array('%d')
    );

    return new WP_REST_Response(array(
        'success' => true,
        'status' => 'revoked',
        'device_id' => $device->device_id,
    ), 200);
}

/*
 * Admin helper: provision a device programmatically.
 * The returned raw key is shown only at provisioning time.
 */
function pv_provision_device($device_id, $device_name = '') {
    global $wpdb;

    $device_id = sanitize_text_field($device_id);
    $device_name = sanitize_text_field($device_name);

    if (!$device_id) {
        return new WP_Error('pv_invalid_device_id', 'Device ID is required.');
    }

    $raw_key = wp_generate_password(48, false, false);
    $hash = hash('sha256', $raw_key);

    $ok = $wpdb->insert(
        pv_device_table(),
        array(
            'device_id' => $device_id,
            'device_name' => $device_name,
            'api_key_hash' => $hash,
            'status' => 'active',
            'created_at' => current_time('mysql', true),
        ),
        array('%s','%s','%s','%s','%s')
    );

    if (!$ok) {
        return new WP_Error('pv_device_exists', 'Could not provision device; device ID may already exist.');
    }

    return array(
        'device_id' => $device_id,
        'api_key' => $raw_key,
        'warning' => 'Store this API key securely. It cannot be recovered from WordPress.',
    );
}


/* =========================
 * Phase 16 — Admin Device Management
 * ========================= */

add_action('admin_menu', 'pv_register_devices_admin_page');

function pv_register_devices_admin_page() {

    add_submenu_page(
        'woocommerce',
        'Payment Verifier Devices',
        'Payment Verifier Devices',
        'manage_woocommerce',
        'payment-verifier-devices',
        'pv_render_devices_page'
    );
}


function pv_render_devices_page() {

    if (!current_user_can('manage_woocommerce')) {
        wp_die('You do not have permission to manage Payment Verifier devices.');
    }

    global $wpdb;

    $table = pv_device_table();

    $notice_key = '';
    $notice_message = '';
    $notice_type = 'success';

    /*
     * Handle admin actions
     */
    if (
        isset($_POST['pv_action']) &&
        isset($_POST['pv_nonce']) &&
        check_admin_referer('pv_device_admin_action', 'pv_nonce')
    ) {

        $action = sanitize_key(
            wp_unslash($_POST['pv_action'])
        );

        /*
         * PROVISION
         */
        if ($action === 'provision') {

            $device_id = sanitize_text_field(
                wp_unslash($_POST['device_id'] ?? '')
            );

            $device_name = sanitize_text_field(
                wp_unslash($_POST['device_name'] ?? '')
            );

            $result = pv_provision_device(
                $device_id,
                $device_name
            );

            if (is_wp_error($result)) {

                $notice_message = $result->get_error_message();
                $notice_type = 'error';

            } else {

                $notice_key = $result['api_key'];
                $notice_message = 'Device provisioned successfully.';
            }
        }

        /*
         * REVOKE
         */
        elseif ($action === 'revoke') {

            $id = absint(
                $_POST['device_db_id'] ?? 0
            );

            if (!$id) {

                $notice_message = 'Invalid device ID.';
                $notice_type = 'error';

            } else {

                $updated = $wpdb->update(
                    $table,
                    array(
                        'status' => 'revoked'
                    ),
                    array(
                        'id' => $id
                    ),
                    array('%s'),
                    array('%d')
                );

                if ($updated === false) {

                    $notice_message = 'Failed to revoke device.';
                    $notice_type = 'error';

                } else {

                    $notice_message = 'Device revoked successfully.';
                }
            }
        }

        /*
         * ROTATE API KEY
         */
        elseif ($action === 'rotate') {

            $id = absint(
                $_POST['device_db_id'] ?? 0
            );

            if (!$id) {

                $notice_message = 'Invalid device ID.';
                $notice_type = 'error';

            } else {

                $raw_key = wp_generate_password(
                    48,
                    false,
                    false
                );

                $hash = hash(
                    'sha256',
                    $raw_key
                );

                $updated = $wpdb->update(
                    $table,
                    array(
                        'api_key_hash' => $hash,
                        'status'       => 'active'
                    ),
                    array(
                        'id' => $id
                    ),
                    array(
                        '%s',
                        '%s'
                    ),
                    array('%d')
                );

                if ($updated === false) {

                    $notice_message = 'Failed to rotate API key.';
                    $notice_type = 'error';

                } else {

                    $notice_key = $raw_key;
                    $notice_message = 'API key rotated successfully. The previous key is now invalid.';
                }
            }
        }
    }

    /*
     * Load devices
     */
    $devices = $wpdb->get_results(
        "SELECT * FROM {$table} ORDER BY id DESC"
    );

    ?>

    <div class="wrap">

        <h1>Payment Verifier Devices</h1>

        <p>
            Provision and manage Android merchant devices that are allowed
            to communicate with Payment Verifier.
        </p>

        <?php if ($notice_message): ?>

            <div class="notice notice-<?php echo esc_attr($notice_type); ?> is-dismissible">

                <p>
                    <strong>
                        <?php echo esc_html($notice_message); ?>
                    </strong>
                </p>

            </div>

        <?php endif; ?>


        <?php if ($notice_key): ?>

            <div class="notice notice-warning">

                <p>
                    <strong>Copy the API key now.</strong>
                    It will not be shown again.
                </p>

                <p>
                    <code
                        style="
                            user-select:all;
                            display:inline-block;
                            padding:10px;
                            background:#fff;
                            font-size:14px;
                        "
                    >
                        <?php echo esc_html($notice_key); ?>
                    </code>
                </p>

            </div>

        <?php endif; ?>


        <!-- Provision New Device -->

        <h2>Provision New Device</h2>

        <form
            method="post"
            style="background:#fff;padding:20px;max-width:700px;"
        >

            <?php wp_nonce_field(
                'pv_device_admin_action',
                'pv_nonce'
            ); ?>

            <input
                type="hidden"
                name="pv_action"
                value="provision"
            >

            <table class="form-table">

                <tr>

                    <th>
                        <label for="pv-device-id">
                            Device ID
                        </label>
                    </th>

                    <td>

                        <input
                            id="pv-device-id"
                            name="device_id"
                            class="regular-text"
                            required
                            placeholder="STORE-DEVICE-01"
                        >

                    </td>

                </tr>

                <tr>

                    <th>
                        <label for="pv-device-name">
                            Device Name
                        </label>
                    </th>

                    <td>

                        <input
                            id="pv-device-name"
                            name="device_name"
                            class="regular-text"
                            placeholder="Main Store Android"
                        >

                    </td>

                </tr>

            </table>

            <?php submit_button(
                'Generate Device API Key'
            ); ?>

        </form>


        <!-- Registered Devices -->

        <h2 style="margin-top:30px;">
            Registered Devices
        </h2>

        <table class="widefat striped">

            <thead>

                <tr>

                    <th>Device</th>
                    <th>Name</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Last Seen</th>
                    <th>Actions</th>

                </tr>

            </thead>

            <tbody>

                <?php if (!$devices): ?>

                    <tr>

                        <td colspan="6">
                            No devices have been provisioned.
                        </td>

                    </tr>

                <?php else: ?>

                    <?php foreach ($devices as $device): ?>

                        <tr>

                            <td>
                                <code>
                                    <?php echo esc_html(
                                        $device->device_id
                                    ); ?>
                                </code>
                            </td>

                            <td>
                                <?php echo esc_html(
                                    $device->device_name
                                ); ?>
                            </td>

                            <td>

                                <strong>
                                    <?php echo esc_html(
                                        strtoupper($device->status)
                                    ); ?>
                                </strong>

                            </td>

                            <td>
                                <?php echo esc_html(
                                    $device->created_at
                                ); ?>
                            </td>

                            <td>
                                <?php echo esc_html(
                                    $device->last_seen_at ?: 'Never'
                                ); ?>
                            </td>

                            <td>

                                <?php if ($device->status === 'active'): ?>

                                    <!-- REVOKE -->

                                    <form
                                        method="post"
                                        style="display:inline-block;margin-right:6px;"
                                    >

                                        <?php wp_nonce_field(
                                            'pv_device_admin_action',
                                            'pv_nonce'
                                        ); ?>

                                        <input
                                            type="hidden"
                                            name="pv_action"
                                            value="revoke"
                                        >

                                        <input
                                            type="hidden"
                                            name="device_db_id"
                                            value="<?php echo esc_attr(
                                                $device->id
                                            ); ?>"
                                        >

                                        <button
                                            type="submit"
                                            class="button button-secondary"
                                            onclick="return confirm('Revoke this device?');"
                                        >
                                            Revoke
                                        </button>

                                    </form>

                                <?php endif; ?>


                                <!-- ROTATE -->

                                <form
                                    method="post"
                                    style="display:inline-block;"
                                >

                                    <?php wp_nonce_field(
                                        'pv_device_admin_action',
                                        'pv_nonce'
                                    ); ?>

                                    <input
                                        type="hidden"
                                        name="pv_action"
                                        value="rotate"
                                    >

                                    <input
                                        type="hidden"
                                        name="device_db_id"
                                        value="<?php echo esc_attr(
                                            $device->id
                                        ); ?>"
                                    >

                                    <button
                                        type="submit"
                                        class="button"
                                        onclick="return confirm('Rotate this device API key? The old key will stop working immediately.');"
                                    >
                                        Rotate Key
                                    </button>

                                </form>

                            </td>

                        </tr>

                    <?php endforeach; ?>

                <?php endif; ?>

            </tbody>

        </table>


        <p style="margin-top:15px;">

            <strong>Security:</strong>

            API keys are stored only as SHA-256 hashes.
            A raw key is shown only immediately after
            provisioning or rotation.

        </p>

    </div>

    <?php
}


/* =========================
 * Phase 18 — Explicit Store Scope
 * ========================= */

function pv_store_table() {
    global $wpdb;
    return $wpdb->prefix . 'pv_stores';
}

function pv_device_store_table() {
    global $wpdb;
    return $wpdb->prefix . 'pv_device_stores';
}

add_action('init', 'pv_maybe_create_scope_tables');
function pv_maybe_create_scope_tables() {
    if (!get_option('pv_scope_schema_version')) {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();

        dbDelta("CREATE TABLE " . pv_store_table() . " (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            store_key VARCHAR(128) NOT NULL,
            store_name VARCHAR(191) NOT NULL DEFAULT '',
            status VARCHAR(20) NOT NULL DEFAULT 'active',
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY store_key (store_key),
            KEY status (status)
        ) {$charset};");

        dbDelta("CREATE TABLE " . pv_device_store_table() . " (
            device_db_id BIGINT UNSIGNED NOT NULL,
            store_id BIGINT UNSIGNED NOT NULL,
            assigned_at DATETIME NOT NULL,
            PRIMARY KEY (device_db_id),
            KEY store_id (store_id)
        ) {$charset};");

        update_option('pv_scope_schema_version', '1');
    }
}

function pv_get_device_store($device) {
    global $wpdb;
    return $wpdb->get_row($wpdb->prepare(
        "SELECT s.* FROM " . pv_store_table() . " s
         INNER JOIN " . pv_device_store_table() . " ds ON ds.store_id=s.id
         WHERE ds.device_db_id=%d AND s.status='active'
         LIMIT 1",
        $device->id
    ));
}

function pv_scoped_device_permission(WP_REST_Request $request) {
    $device = pv_device_permission($request);
    if (is_wp_error($device)) return $device;

    $store = pv_get_device_store($device);
    if (!$store) {
        return new WP_Error(
            'pv_device_unassigned',
            'Device is authenticated but has no active store assignment.',
            array('status' => 403)
        );
    }

    $request->set_param('_pv_authenticated_device', $device);

    return $device;
}

add_action('rest_api_init', function () {
    register_rest_route('payment-verifier/v1', '/scope', array(
        'methods' => WP_REST_Server::READABLE,
        'callback' => 'pv_scope_info',
        'permission_callback' => 'pv_scoped_device_permission',
    ));
});

function pv_scope_info(WP_REST_Request $request) {
    $device = pv_device_from_request($request);
    if (is_wp_error($device)) return $device;

    $store = pv_get_device_store($device);
    if (!$store) {
        return new WP_Error('pv_device_unassigned', 'No active store assignment.', array('status' => 403));
    }

    return new WP_REST_Response(array(
        'success' => true,
        'device_id' => $device->device_id,
        'store_id' => (int) $store->id,
        'store_key' => $store->store_key,
        'store_name' => $store->store_name,
        'server_time' => time(),
    ), 200);
}


/* =========================
 * Secure local verification bridge
 * ========================= */
function pv_verification_requests_table(){ global $wpdb; return $wpdb->prefix.'pv_verification_requests'; }
function pv_normalize_phone($v){ $d=preg_replace('/\D+/','',(string)$v); if(strpos($d,'880')===0)$d=substr($d,2); if(strpos($d,'0')===0)$d=substr($d,1); return $d; }
function pv_encrypt_for_device($plaintext,$public_key){ $out=''; if(!$public_key || !openssl_public_encrypt($plaintext,$out,$public_key,OPENSSL_PKCS1_OAEP_PADDING)) return false; return base64_encode($out); }

add_action('rest_api_init', function(){
 register_rest_route('payment-verifier/v1','/device/register-key',array('methods'=>WP_REST_Server::CREATABLE,'permission_callback'=>'pv_device_permission','callback'=>function($r){global $wpdb;$d=pv_device_from_request($r);if(is_wp_error($d))return $d;$key=trim((string)($r->get_json_params()['public_key']??''));$raw=base64_decode($key,true);if(!$raw)return new WP_Error('pv_invalid_public_key','Invalid public key.',array('status'=>422));$pem="-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($raw),64,"\n")."-----END PUBLIC KEY-----\n";if(!openssl_pkey_get_public($pem))return new WP_Error('pv_invalid_public_key','Invalid RSA public key.',array('status'=>422));$wpdb->update(pv_device_table(),array('public_key'=>$pem),array('id'=>$d->id),array('%s'),array('%d'));return array('success'=>true,'status'=>'key_registered');}));
 register_rest_route('payment-verifier/v1','/verification/pending',array(
  'methods'=>WP_REST_Server::READABLE,'permission_callback'=>'pv_device_permission','callback'=>function($r){
   global $wpdb; $d=pv_device_from_request($r); if(is_wp_error($d))return $d;
   $row=$wpdb->get_row($wpdb->prepare("SELECT * FROM ".pv_verification_requests_table()." WHERE status='pending' AND expires_at>%s AND (device_id IS NULL OR device_id=%s) ORDER BY id ASC LIMIT 1",current_time('mysql',true),$d->device_id));
   if(!$row)return array('success'=>true,'pending'=>false);
   $pub=$d->public_key; if(!$pub)return new WP_Error('pv_device_key_missing','Device public key is not registered.',array('status'=>409));
   $payload=wp_json_encode(array('phone'=>$row->phone,'transaction_id'=>$row->transaction_value,'request_id'=>$row->request_id,'expires_at'=>strtotime($row->expires_at)));
   $enc=pv_encrypt_for_device($payload,$pub); if($enc===false)return new WP_Error('pv_encryption_failed','Unable to encrypt verification request.',array('status'=>500));
   $wpdb->update(pv_verification_requests_table(),array('device_id'=>$d->device_id),array('id'=>$row->id),array('%s'),array('%d'));
   return array('success'=>true,'pending'=>true,'request_id'=>$row->request_id,'payload'=>$enc,'expires_at'=>strtotime($row->expires_at));
  }
 ));
 register_rest_route('payment-verifier/v1','/verification/result',array(
  'methods'=>WP_REST_Server::CREATABLE,'permission_callback'=>'pv_device_permission','callback'=>function($r){
   global $wpdb; $d=pv_device_from_request($r); if(is_wp_error($d))return $d; $x=$r->get_json_params(); $rid=sanitize_text_field($x['request_id']??''); $approved=!empty($x['approved']); $sig=base64_decode((string)($x['signature']??''),true); $reason=sanitize_key($x['reason_code']??'');
   $row=$wpdb->get_row($wpdb->prepare("SELECT * FROM ".pv_verification_requests_table()." WHERE request_id=%s AND status='pending' AND (device_id IS NULL OR device_id=%s) LIMIT 1",$rid,$d->device_id)); if(!$row)return new WP_Error('pv_request_not_found','Verification request is invalid or expired.',array('status'=>404)); if(strtotime($row->expires_at)<time())return new WP_Error('pv_request_expired','Verification request expired.',array('status'=>410)); if(!$sig)return new WP_Error('pv_bad_signature','Signature is required.',array('status'=>401)); $canonical=$rid.'|'.($approved?'1':'0').'|'.$reason; $pub=$d->public_key; if(!$pub||openssl_verify($canonical,$sig,$pub,OPENSSL_ALGO_SHA256)!==1)return new WP_Error('pv_bad_signature','Invalid device signature.',array('status'=>401));
   if(!$approved){$wpdb->update(pv_verification_requests_table(),array('status'=>'rejected','reason_code'=>$reason,'completed_at'=>current_time('mysql',true)),array('id'=>$row->id),array('%s','%s','%s'),array('%d'));return array('success'=>true,'status'=>'rejected');}
   $phone=pv_normalize_phone($row->phone); $orders=wc_get_orders(array('status'=>array('pending','on-hold'),'limit'=>50,'return'=>'objects','meta_query'=>array(array('key'=>'_billing_phone','compare'=>'EXISTS')))); $matches=array(); foreach($orders as $o){if(pv_normalize_phone($o->get_billing_phone())===$phone && in_array(sanitize_key($o->get_meta('_pv_provider')),array('bkash','nagad'),true) && $o->get_meta('_pv_verification_status')!=='verified')$matches[]=$o;}
   if(count($matches)!==1){$wpdb->update(pv_verification_requests_table(),array('status'=>'rejected','reason_code'=>count($matches)?'ambiguous_order':'order_not_found','completed_at'=>current_time('mysql',true)),array('id'=>$row->id),array('%s','%s','%s'),array('%d'));return new WP_Error(count($matches)?'pv_ambiguous_order':'pv_order_not_found',count($matches)?'Multiple pending orders match this phone number.':'No pending Payment Verifier order matches this phone number.',array('status'=>409));}
   $o=$matches[0]; $txn=pv_normalize_transaction_id($row->transaction_value); $exists=$wpdb->get_var($wpdb->prepare("SELECT id FROM {$wpdb->prefix}pv_payments WHERE transaction_id=%s LIMIT 1",$txn)); if($exists)return new WP_Error('pv_duplicate','Transaction ID already exists.',array('status'=>409)); $now=current_time('mysql',true); $wpdb->insert($wpdb->prefix.'pv_payments',array('order_id'=>$o->get_id(),'provider'=>sanitize_key($o->get_meta('_pv_provider')),'amount'=>(float)$o->get_total(),'transaction_id'=>$txn,'device_id'=>$d->device_id,'status'=>'verified','verified_at'=>$now,'created_at'=>$now,'updated_at'=>$now),array('%d','%s','%f','%s','%s','%s','%s','%s','%s')); $o->update_meta_data('_pv_transaction_id',$txn);$o->update_meta_data('_pv_verified_transaction_id',$txn);$o->update_meta_data('_pv_verification_status','verified');$o->update_meta_data('_pv_verified','yes');$o->save();$o->payment_complete($txn);$o->add_order_note('Payment verified by secure local Android SMS verification. Transaction ID: '.$txn);$wpdb->update(pv_verification_requests_table(),array('status'=>'approved','completed_at'=>$now),array('id'=>$row->id),array('%s','%s'),array('%d'));return array('success'=>true,'status'=>'approved');
  }
 ));

 add_shortcode('pv_verify_payment',function(){ $nonce=wp_create_nonce('pv_verify_payment'); ob_start(); ?>
 <div id="pv-secure-verify" style="max-width:520px;padding:24px;border:1px solid #ddd;border-radius:12px"><h3>Verify Payment</h3><p>Enter the payer phone number and transaction ID. No SMS content is uploaded.</p><input id="pv-phone" type="tel" placeholder="01XXXXXXXXX" style="width:100%;margin:6px 0;padding:10px"><input id="pv-txn" type="text" placeholder="Transaction ID" style="width:100%;margin:6px 0;padding:10px"><button id="pv-verify-btn" style="padding:10px 18px">Verify Payment</button><div id="pv-verify-status" style="margin-top:12px"></div></div>
 <script>(function(){const n='<?php echo esc_js($nonce);?>',s=document.getElementById('pv-verify-status'),b=document.getElementById('pv-verify-btn');b.onclick=async()=>{s.textContent='Creating secure verification request...';const f=new FormData();f.append('action','pv_create_verification');f.append('nonce',n);f.append('phone',document.getElementById('pv-phone').value);f.append('transaction_id',document.getElementById('pv-txn').value);let r=await fetch('<?php echo esc_url(admin_url('admin-ajax.php'));?>',{method:'POST',body:f});let j=await r.json();if(!j.success){s.textContent=j.data?.message||'Unable to create request.';return}const id=j.data.request_id; s.textContent='Waiting for secure Android verification...';let tries=0;const poll=async()=>{if(++tries>90){s.textContent='Verification timed out.';return}let q=await fetch('<?php echo esc_url(rest_url('payment-verifier/v1/verification-status'));?>?request_id='+encodeURIComponent(id));let x=await q.json();if(x.status==='approved'){s.textContent='Payment approved.';return}if(x.status==='rejected'){s.textContent='Payment rejected: '+(x.reason||'not matched');return}setTimeout(poll,2000)};poll()};})();</script>
 <?php return ob_get_clean();});
 add_action('wp_ajax_nopriv_pv_create_verification','pv_create_verification'); add_action('wp_ajax_pv_create_verification','pv_create_verification');
 function pv_create_verification(){if(!wp_verify_nonce($_POST['nonce']??'','pv_verify_payment'))wp_send_json_error(array('message'=>'Security check failed.'),403);global $wpdb;$phone=pv_normalize_phone(sanitize_text_field(wp_unslash($_POST['phone']??'')));$txn=pv_normalize_transaction_id($_POST['transaction_id']??'');if(strlen($phone)<10||strlen($txn)<4)wp_send_json_error(array('message'=>'Valid phone number and transaction ID are required.'),422);$rid=wp_generate_uuid4();$now=time();$wpdb->insert(pv_verification_requests_table(),array('request_id'=>$rid,'phone'=>$phone,'phone_hash'=>hash('sha256',$phone),'transaction_hash'=>hash('sha256',$txn),'transaction_value'=>$txn,'status'=>'pending','created_at'=>gmdate('Y-m-d H:i:s',$now),'expires_at'=>gmdate('Y-m-d H:i:s',$now+180)),array('%s','%s','%s','%s','%s','%s','%s','%s'));wp_send_json_success(array('request_id'=>$rid));}
 register_rest_route('payment-verifier/v1','/verification-status',array('methods'=>WP_REST_Server::READABLE,'permission_callback'=>'__return_true','callback'=>function($r){global $wpdb;$id=sanitize_text_field($r->get_param('request_id'));$x=$wpdb->get_row($wpdb->prepare("SELECT status,reason_code,expires_at FROM ".pv_verification_requests_table()." WHERE request_id=%s LIMIT 1",$id));if(!$x)return array('status'=>'not_found');if($x->status==='pending'&&strtotime($x->expires_at)<time()){$wpdb->update(pv_verification_requests_table(),array('status'=>'expired'),array('request_id'=>$id),array('%s'),array('%s'));return array('status'=>'expired');}return array('status'=>$x->status,'reason'=>$x->reason_code); }));
});

/* =========================
 * Phase 23 — Dynamic SMS Sender Rules
 * ========================= */

function pv_sms_sender_rules() {

    $rules = get_option('pv_sms_sender_rules', array());

    if (!is_array($rules)) {
        return array();
    }

    return $rules;
}


/**
 * Return SMS sender rules to an authenticated Android device.
 *
 * Only the authenticated device's assigned store can request these rules.
 */
function pv_sms_rules(WP_REST_Request $request) {

    $device = $request->get_param('_pv_authenticated_device');

    if (!$device || !is_object($device)) {
        return new WP_Error(
            'pv_unauthorized',
            'Device authentication failed.',
            array('status' => 401)
        );
    }

    $store = pv_get_device_store($device);

    if (!$store) {
        return new WP_Error(
            'pv_device_unassigned',
            'Device has no active store assignment.',
            array('status' => 403)
        );
    }

    $rules = pv_sms_sender_rules();

    return new WP_REST_Response(
        array(
            'success' => true,
            'store_id' => (int) $store->id,
            'providers' => $rules,
            'server_time' => time(),
        ),
        200
    );
}


/**
 * Register SMS rules endpoint.
 */
add_action('rest_api_init', function () {

    register_rest_route(
        'payment-verifier/v1',
        '/sms-rules',
        array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => 'pv_sms_rules',
            'permission_callback' => 'pv_scoped_device_permission',
        )
    );

});

function pv_install_default_sms_sender_rules() {

    /**if (get_option('pv_sms_sender_rules', null) !== null) {
        return;
    }**/

    $rules = array(
        array(
            'provider' => 'bkash',
            'sender_ids' => array(
                'BKASH',
                '16247',
            ),
        ),

        array(
            'provider' => 'nagad',
            'sender_ids' => array(
                'NAGAD',
                '16167',
            ),
        ),

        array(
            'provider' => 'rocket',
            'sender_ids' => array(
                'ROCKET',
            ),
        ),
    );

    update_option(
        'pv_sms_sender_rules',
        $rules,
        false
    );
}

add_action(
    'init',
    'pv_install_default_sms_sender_rules',
    5
);

function pv_create_store($store_key, $store_name = '') {
    global $wpdb;
    $store_key = sanitize_key($store_key);
    $store_name = sanitize_text_field($store_name);

    if (!$store_key) {
        return new WP_Error('pv_invalid_store', 'Store key is required.');
    }

    $ok = $wpdb->insert(
        pv_store_table(),
        array(
            'store_key' => $store_key,
            'store_name' => $store_name,
            'status' => 'active',
            'created_at' => current_time('mysql', true),
        ),
        array('%s','%s','%s','%s')
    );

    if (!$ok) {
        return new WP_Error('pv_store_exists', 'Store already exists or could not be created.');
    }

    return (int) $wpdb->insert_id;
}

function pv_assign_device_to_store($device_db_id, $store_id) {
    global $wpdb;

    $device_db_id = absint($device_db_id);
    $store_id = absint($store_id);

    if (!$device_db_id || !$store_id) {
        return new WP_Error('pv_invalid_scope', 'Device and store are required.');
    }

    $store = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM " . pv_store_table() . " WHERE id=%d AND status='active'",
        $store_id
    ));
    if (!$store) {
        return new WP_Error('pv_invalid_store', 'Active store not found.');
    }

    $wpdb->replace(
        pv_device_store_table(),
        array(
            'device_db_id' => $device_db_id,
            'store_id' => $store_id,
            'assigned_at' => current_time('mysql', true),
        ),
        array('%d','%d','%s')
    );

    return true;
}


add_action('admin_menu', 'pv_register_scope_admin_page');
function pv_register_scope_admin_page() {
    add_submenu_page(
        'woocommerce',
        'Payment Verifier Store Scope',
        'Payment Verifier Scope',
        'manage_woocommerce',
        'payment-verifier-scope',
        'pv_render_scope_admin_page'
    );
}

function pv_render_scope_admin_page() {
    if (!current_user_can('manage_woocommerce')) {
        wp_die('You do not have permission to manage Payment Verifier scope.');
    }

    global $wpdb;
    $message = '';

    if (isset($_POST['pv_scope_action']) && check_admin_referer('pv_scope_admin_action', 'pv_scope_nonce')) {
        $action = sanitize_key(wp_unslash($_POST['pv_scope_action']));

        if ($action === 'create_store') {
            $key = sanitize_key(wp_unslash($_POST['store_key'] ?? ''));
            $name = sanitize_text_field(wp_unslash($_POST['store_name'] ?? ''));
            $result = pv_create_store($key, $name);
            $message = is_wp_error($result) ? $result->get_error_message() : 'Store created.';
        }

        if ($action === 'assign_device') {
            $device_id = absint($_POST['device_db_id'] ?? 0);
            $store_id = absint($_POST['store_id'] ?? 0);
            $result = pv_assign_device_to_store($device_id, $store_id);
            $message = is_wp_error($result) ? $result->get_error_message() : 'Device assigned to store.';
        }
    }

    $stores = $wpdb->get_results("SELECT * FROM " . pv_store_table() . " ORDER BY id ASC");
    $devices = $wpdb->get_results(
        "SELECT d.*, s.store_name, s.store_key
         FROM " . pv_device_table() . " d
         LEFT JOIN " . pv_device_store_table() . " ds ON ds.device_db_id=d.id
         LEFT JOIN " . pv_store_table() . " s ON s.id=ds.store_id
         ORDER BY d.id DESC"
    );

    echo '<div class="wrap"><h1>Payment Verifier Store Scope</h1>';
    if ($message) {
        echo '<div class="notice notice-info is-dismissible"><p>' . esc_html($message) . '</p></div>';
    }

    echo '<h2>Create Store Scope</h2>';
    echo '<form method="post" style="background:#fff;padding:20px;max-width:700px;">';
    wp_nonce_field('pv_scope_admin_action', 'pv_scope_nonce');
    echo '<input type="hidden" name="pv_scope_action" value="create_store">';
    echo '<table class="form-table"><tr><th>Store Key</th><td><input name="store_key" required class="regular-text" placeholder="store-a"></td></tr>';
    echo '<tr><th>Store Name</th><td><input name="store_name" class="regular-text" placeholder="Main Store"></td></tr></table>';
    submit_button('Create Store');
    echo '</form>';

    echo '<h2>Stores</h2><table class="widefat striped"><thead><tr><th>ID</th><th>Key</th><th>Name</th><th>Status</th></tr></thead><tbody>';
    if (!$stores) {
        echo '<tr><td colspan="4">No stores configured.</td></tr>';
    } else {
        foreach ($stores as $store) {
            echo '<tr><td>' . esc_html($store->id) . '</td><td><code>' . esc_html($store->store_key) . '</code></td><td>' .
                esc_html($store->store_name) . '</td><td>' . esc_html(strtoupper($store->status)) . '</td></tr>';
        }
    }
    echo '</tbody></table>';

    echo '<h2 style="margin-top:30px;">Assign Devices</h2>';
    foreach ($devices as $device) {
        echo '<form method="post" style="background:#fff;padding:15px;margin-bottom:10px;max-width:900px;">';
        wp_nonce_field('pv_scope_admin_action', 'pv_scope_nonce');
        echo '<input type="hidden" name="pv_scope_action" value="assign_device">';
        echo '<input type="hidden" name="device_db_id" value="' . esc_attr($device->id) . '">';
        echo '<strong>' . esc_html($device->device_name ?: $device->device_id) . '</strong> ';
        echo '<code>' . esc_html($device->device_id) . '</code> — Current: <strong>' .
            esc_html($device->store_name ?: 'Unassigned') . '</strong> ';
        echo '<select name="store_id" required><option value="">Select store</option>';
        foreach ($stores as $store) {
            $selected = ($device->store_key === $store->store_key) ? ' selected' : '';
            echo '<option value="' . esc_attr($store->id) . '"' . $selected . '>' .
                esc_html($store->store_name . ' (' . $store->store_key . ')') . '</option>';
        }
        echo '</select> ';
        submit_button('Assign', 'secondary', '', false);
        echo '</form>';
    }

    echo '<p><strong>Security boundary:</strong> authenticated devices without an active store assignment cannot access scoped order synchronization.</p>';
    echo '</div>';
}


add_action('pv_cleanup_idempotency', 'pv_cleanup_idempotency_records');
function pv_cleanup_idempotency_records() {
    global $wpdb;
    $wpdb->query($wpdb->prepare(
        "DELETE FROM {$wpdb->prefix}pv_idempotency WHERE expires_at < %s",
        current_time('mysql', true)
    ));
}

if (!wp_next_scheduled('pv_cleanup_idempotency')) {
    wp_schedule_event(time() + HOUR_IN_SECONDS, 'hourly', 'pv_cleanup_idempotency');
}

/* Phase 9 compatibility marker: pv_order_amount_mismatch; Phase 15 header: X-PV-Device-ID. */

/* Historical contract markers retained: pv_amount_mismatch; pv_order_transaction_mismatch. */

/* Historical contract marker: pv_replay. */


/* =========================
 * Phase 21 — Staging Integration Health
 * ========================= */

add_action('rest_api_init', function () {
    register_rest_route('payment-verifier/v1', '/health', array(
        'methods' => WP_REST_Server::READABLE,
        'callback' => 'pv_health_check',
        'permission_callback' => 'pv_scoped_device_permission',
    ));
});

function pv_health_check(WP_REST_Request $request) {
    $started = microtime(true);
    $correlation_id = pv_request_correlation_id($request);
    $device = pv_device_from_request($request);
    if (is_wp_error($device)) return $device;

    $store = pv_get_device_store($device);
    if (!$store) {
        return new WP_Error(
            'pv_device_unassigned',
            'Device has no active store assignment.',
            array('status' => 403)
        );
    }

    global $wpdb;

    $checks = array(
        'wordpress' => true,
        'woocommerce' => class_exists('WooCommerce'),
        'database' => (bool) $wpdb->get_var('SELECT 1'),
        'devices_table' => (bool) $wpdb->get_var("SHOW TABLES LIKE '" . esc_sql(pv_device_table()) . "'"),
        'stores_table' => (bool) $wpdb->get_var("SHOW TABLES LIKE '" . esc_sql(pv_store_table()) . "'"),
        'device_store_table' => (bool) $wpdb->get_var("SHOW TABLES LIKE '" . esc_sql(pv_device_store_table()) . "'"),
    );

    $ok = !in_array(false, $checks, true);

    $duration = (int) round((microtime(true) - $started) * 1000);
    pv_audit(array(
        'correlation_id' => $correlation_id,
        'event_type' => 'health_check',
        'outcome' => $ok ? 'success' : 'degraded',
        'device_id' => $device->device_id,
        'store_id' => $store->id,
        'http_status' => $ok ? 200 : 503,
        'duration_ms' => $duration,
        'message' => $ok ? 'Integration healthy.' : 'Integration degraded.',
    ));

    return pv_observable_response(array(
        'success' => $ok,
        'status' => $ok ? 'healthy' : 'degraded',
        'checks' => $checks,
        'device' => array(
            'device_id' => $device->device_id,
            'status' => $device->status,
        ),
        'store' => array(
            'store_id' => (int) $store->id,
            'store_key' => $store->store_key,
        ),
        'server_time' => time(),
        'plugin_version' => defined('PV_VERSION') ? PV_VERSION : 'unknown',
    ), $ok ? 200 : 503, $correlation_id);
}


add_action('admin_menu', 'pv_register_integration_admin_page');
function pv_register_integration_admin_page() {
    add_submenu_page(
        'woocommerce',
        'Payment Verifier Integration',
        'Payment Verifier Integration',
        'manage_woocommerce',
        'payment-verifier-integration',
        'pv_render_integration_admin_page'
    );
}

function pv_render_integration_admin_page() {
    if (!current_user_can('manage_woocommerce')) {
        wp_die('You do not have permission to inspect Payment Verifier integration.');
    }

    global $wpdb;

    $checks = array();

    $checks['WooCommerce'] = class_exists('WooCommerce');
    $checks['Devices table'] = (bool) $wpdb->get_var("SHOW TABLES LIKE '" . esc_sql(pv_device_table()) . "'");
    $checks['Stores table'] = (bool) $wpdb->get_var("SHOW TABLES LIKE '" . esc_sql(pv_store_table()) . "'");
    $checks['Device-store table'] = (bool) $wpdb->get_var("SHOW TABLES LIKE '" . esc_sql(pv_device_store_table()) . "'");
    $checks['REST API'] = function_exists('rest_url');

    $device_count = (int) $wpdb->get_var("SELECT COUNT(*) FROM " . pv_device_table());
    $assigned_count = (int) $wpdb->get_var(
        "SELECT COUNT(*) FROM " . pv_device_store_table()
    );
    $active_count = (int) $wpdb->get_var(
        "SELECT COUNT(*) FROM " . pv_device_table() . " WHERE status='active'"
    );

    echo '<div class="wrap"><h1>Payment Verifier Integration</h1>';
    echo '<p>Use this page before connecting a staging Android device.</p>';

    echo '<table class="widefat striped" style="max-width:900px;"><thead><tr><th>Check</th><th>Status</th></tr></thead><tbody>';
    foreach ($checks as $name => $ok) {
        echo '<tr><td>' . esc_html($name) . '</td><td>' .
            ($ok ? '<span style="color:green;font-weight:bold;">PASS</span>' :
            '<span style="color:#b32d2e;font-weight:bold;">FAIL</span>') .
            '</td></tr>';
    }
    echo '</tbody></table>';

    echo '<h2>Device Readiness</h2>';
    echo '<ul>';
    echo '<li>Total registered devices: <strong>' . esc_html($device_count) . '</strong></li>';
    echo '<li>Active devices: <strong>' . esc_html($active_count) . '</strong></li>';
    echo '<li>Store assignments: <strong>' . esc_html($assigned_count) . '</strong></li>';
    echo '</ul>';

    echo '<h2>Staging Test Sequence</h2>';
    echo '<ol>';
    echo '<li>Create a staging store scope.</li>';
    echo '<li>Provision an Android test device.</li>';
    echo '<li>Assign the device to the staging store.</li>';
    echo '<li>Call <code>/wp-json/payment-verifier/v1/health</code>.</li>';
    echo '<li>Call <code>/wp-json/payment-verifier/v1/scope</code>.</li>';
    echo '<li>Create a WooCommerce test order.</li>';
    echo '<li>Sync the order to Android.</li>';
    echo '<li>Submit a controlled test payment event.</li>';
    echo '<li>Confirm verification and WooCommerce status transition.</li>';
    echo '<li>Repeat the same request to confirm idempotency.</li>';
    echo '</ol>';

    echo '<p><strong>Production rule:</strong> perform these tests on staging first. Do not use real customer/payment credentials during integration testing.</p>';
    echo '</div>';
}


/* =========================
 * Phase 22 — Verification Observability
 * ========================= */

function pv_correlation_id() {
    $header = isset($_SERVER['HTTP_X_PV_CORRELATION_ID'])
        ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_PV_CORRELATION_ID']))
        : '';
    if ($header && preg_match('/^[A-Za-z0-9._:-]{8,80}$/', $header)) {
        return $header;
    }
    return 'pv-' . wp_generate_uuid4();
}

function pv_audit_table() {
    global $wpdb;
    return $wpdb->prefix . 'pv_audit_log';
}

add_action('init', 'pv_maybe_create_audit_table');
function pv_maybe_create_audit_table() {
    if (!get_option('pv_audit_schema_version')) {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();

        dbDelta("CREATE TABLE " . pv_audit_table() . " (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            correlation_id VARCHAR(80) NOT NULL,
            event_type VARCHAR(80) NOT NULL,
            outcome VARCHAR(30) NOT NULL,
            device_id VARCHAR(191) NOT NULL DEFAULT '',
            store_id BIGINT UNSIGNED NULL,
            order_id BIGINT UNSIGNED NULL,
            transaction_id VARCHAR(191) NOT NULL DEFAULT '',
            idempotency_key VARCHAR(191) NOT NULL DEFAULT '',
            http_status SMALLINT UNSIGNED NULL,
            duration_ms INT UNSIGNED NULL,
            error_code VARCHAR(100) NOT NULL DEFAULT '',
            message TEXT NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY correlation_id (correlation_id),
            KEY event_type (event_type),
            KEY device_id (device_id),
            KEY store_id (store_id),
            KEY order_id (order_id),
            KEY transaction_id (transaction_id),
            KEY created_at (created_at)
        ) {$charset};");

        update_option('pv_audit_schema_version', '1');
    }
}

function pv_audit($data) {
    global $wpdb;

    $defaults = array(
        'correlation_id' => pv_correlation_id(),
        'event_type' => 'unknown',
        'outcome' => 'unknown',
        'device_id' => '',
        'store_id' => null,
        'order_id' => null,
        'transaction_id' => '',
        'idempotency_key' => '',
        'http_status' => null,
        'duration_ms' => null,
        'error_code' => '',
        'message' => '',
        'created_at' => current_time('mysql', true),
    );
    $row = wp_parse_args($data, $defaults);

    $wpdb->insert(
        pv_audit_table(),
        array(
            'correlation_id' => sanitize_text_field($row['correlation_id']),
            'event_type' => sanitize_key($row['event_type']),
            'outcome' => sanitize_key($row['outcome']),
            'device_id' => sanitize_text_field($row['device_id']),
            'store_id' => $row['store_id'] === null ? null : absint($row['store_id']),
            'order_id' => $row['order_id'] === null ? null : absint($row['order_id']),
            'transaction_id' => sanitize_text_field($row['transaction_id']),
            'idempotency_key' => sanitize_text_field($row['idempotency_key']),
            'http_status' => $row['http_status'] === null ? null : absint($row['http_status']),
            'duration_ms' => $row['duration_ms'] === null ? null : absint($row['duration_ms']),
            'error_code' => sanitize_key($row['error_code']),
            'message' => wp_strip_all_tags($row['message']),
            'created_at' => $row['created_at'],
        ),
        array('%s','%s','%s','%s','%d','%d','%s','%s','%d','%d','%s','%s','%s')
    );
}

function pv_request_correlation_id(WP_REST_Request $request) {
    $value = $request->get_header('X-PV-Correlation-ID');
    if ($value && preg_match('/^[A-Za-z0-9._:-]{8,80}$/', $value)) {
        return sanitize_text_field($value);
    }
    return pv_correlation_id();
}

function pv_observable_response($data, $status, $correlation_id) {
    $response = new WP_REST_Response($data, $status);
    $response->header('X-PV-Correlation-ID', $correlation_id);
    return $response;
}

add_filter('rest_post_dispatch', function ($response, $server, $request) {
    if (strpos((string) $request->get_route(), '/payment-verifier/v1/') !== 0) {
        return $response;
    }
    if ($response instanceof WP_REST_Response) {
        $headers = $response->get_headers();
        if (!isset($headers['X-PV-Correlation-ID'])) {
            $response->header('X-PV-Correlation-ID', pv_request_correlation_id($request));
        }
    }
    return $response;
}, 10, 3);


add_action('admin_menu', 'pv_register_audit_admin_page');
function pv_register_audit_admin_page() {
    add_submenu_page(
        'woocommerce',
        'Payment Verifier Audit Log',
        'Payment Verifier Audit',
        'manage_woocommerce',
        'payment-verifier-audit',
        'pv_render_audit_admin_page'
    );
}

function pv_render_audit_admin_page() {
    if (!current_user_can('manage_woocommerce')) {
        wp_die('You do not have permission to view Payment Verifier audit logs.');
    }

    global $wpdb;
    $rows = $wpdb->get_results(
        "SELECT * FROM " . pv_audit_table() . " ORDER BY id DESC LIMIT 200"
    );

    echo '<div class="wrap"><h1>Payment Verifier Audit Log</h1>';
    echo '<p>Latest 200 operational/security events. Sensitive credentials are never stored here.</p>';
    echo '<table class="widefat striped"><thead><tr>';
    echo '<th>Time</th><th>Correlation</th><th>Event</th><th>Outcome</th><th>Device</th><th>Store</th><th>Order</th><th>TXN</th><th>Status</th><th>Duration</th><th>Error</th>';
    echo '</tr></thead><tbody>';

    if (!$rows) {
        echo '<tr><td colspan="11">No audit events yet.</td></tr>';
    } else {
        foreach ($rows as $row) {
            echo '<tr>';
            echo '<td>' . esc_html($row->created_at) . '</td>';
            echo '<td><code>' . esc_html($row->correlation_id) . '</code></td>';
            echo '<td>' . esc_html($row->event_type) . '</td>';
            echo '<td>' . esc_html($row->outcome) . '</td>';
            echo '<td>' . esc_html($row->device_id) . '</td>';
            echo '<td>' . esc_html($row->store_id ?: '-') . '</td>';
            echo '<td>' . esc_html($row->order_id ?: '-') . '</td>';
            echo '<td>' . esc_html($row->transaction_id ?: '-') . '</td>';
            echo '<td>' . esc_html($row->http_status ?: '-') . '</td>';
            echo '<td>' . esc_html($row->duration_ms !== null ? $row->duration_ms . ' ms' : '-') . '</td>';
            echo '<td>' . esc_html($row->error_code ?: '-') . '</td>';
            echo '</tr>';
        }
    }

    echo '</tbody></table></div>';
}


require_once __DIR__ . '/includes/pv-staging-diagnostics.php';

add_action('admin_menu', function () {
    if (function_exists('pv_render_staging_diagnostics')) {
        add_submenu_page(
            'woocommerce',
            __('Payment Verifier Diagnostics', 'payment-verifier'),
            __('Payment Verifier Diagnostics', 'payment-verifier'),
            'manage_woocommerce',
            'payment-verifier-diagnostics',
            'pv_render_staging_diagnostics'
        );
    }
});

error_log('PV DEBUG: PAYMENT-SMS REGISTRATION FILE LOADED');

add_action('rest_api_init', function () {

    error_log('PV DEBUG: rest_api_init fired for payment-sms');

    register_rest_route(
        'payment-verifier/v1',
        '/payment-sms',
        array(
            'methods'  => WP_REST_Server::CREATABLE,
            'callback' => 'pv_receive_payment_sms',

            'permission_callback' => function ($request) {

                $https = pv_require_https($request);

                if (is_wp_error($https)) {
                    return $https;
                }

                $result = pv_scoped_device_permission($request);

                if (is_wp_error($result)) {
                    return $result;
                }

                $device = $request->get_param('_pv_authenticated_device');

                if (!$device || !is_object($device)) {
                    return new WP_Error(
                        'pv_unauthorized',
                        'Device authentication failed.',
                        array('status' => 401)
                    );
                }

                return pv_verification_rate_limit($device->device_id);
            },
        )
    );

    error_log('PV DEBUG: payment-sms route registered');
});

/**
 * Declare WooCommerce Checkout Block compatibility.
 */
add_action('before_woocommerce_init', function () {

    if (class_exists('\Automattic\WooCommerce\Utilities\FeaturesUtil')) {

        \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility(
            'cart_checkout_blocks',
            __FILE__,
            true
        );
    }
});


/**
 * WooCommerce Checkout Block support.
 *
 * bKash and Nagad are registered as two independent payment methods. The
 * provider is therefore selected by the gateway itself, not by a checkout
 * dropdown field.
 */
add_action(
    'woocommerce_blocks_loaded',
    function () {

        error_log('PV BLOCKS: woocommerce_blocks_loaded fired');

        if (!class_exists(
            'Automattic\\WooCommerce\\Blocks\\Payments\\Integrations\\AbstractPaymentMethodType'
        )) {
            error_log('PV BLOCKS: AbstractPaymentMethodType NOT FOUND');
            return;
        }

        error_log('PV BLOCKS: AbstractPaymentMethodType FOUND');

        require_once plugin_dir_path(__FILE__) .
            'includes/class-pv-blocks-payment-method.php';

        error_log('PV BLOCKS: payment method classes loaded');

        /*
         * Register the script before WooCommerce Blocks collects it as a
         * dependency of wc-checkout-block-frontend.
         */
        $script_path = plugin_dir_path(__FILE__) .
            'assets/js/payment-verifier-blocks.js';

        $script_url = plugin_dir_url(__FILE__) .
            'assets/js/payment-verifier-blocks.js';

        $version = file_exists($script_path)
            ? filemtime($script_path)
            : PV_VERSION;

        wp_register_script(
            'payment-verifier-blocks',
            $script_url,
            array(
                'wc-blocks-registry',
                'wc-settings',
                'wp-element',
            ),
            $version,
            true
        );

        error_log('PV BLOCKS: payment method script registered');

        add_action(
            'woocommerce_blocks_payment_method_type_registration',
            function (
                Automattic\WooCommerce\Blocks\Payments\PaymentMethodRegistry $payment_method_registry
            ) {

                error_log('PV BLOCKS: registration hook fired');

                $payment_method_registry->register(
                    new PV_Blocks_Payment_Method_Bkash()
                );

                error_log('PV BLOCKS: bKash payment method registered');

                $payment_method_registry->register(
                    new PV_Blocks_Payment_Method_Nagad()
                );

                error_log('PV BLOCKS: Nagad payment method registered');
            }
        );
    }
);

// Bkash Nagad payment method registration complete.

function pv_get_sms_provider_config() {

    $default = array(
        'bkash' => array(
            'enabled'    => true,
            'sender_ids' => array('BKASH'),
        ),

        'nagad' => array(
            'enabled'    => true,
            'sender_ids' => array('NAGAD'),
        ),

        'rocket' => array(
            'enabled'    => true,
            'sender_ids' => array('ROCKET'),
        ),
    );

    $config = get_option('pv_sms_provider_config', array());

    if (!is_array($config)) {
        return $default;
    }

    return wp_parse_args($config, $default);
}

function pv_normalize_sms_sender($sender) {

    $sender = strtoupper(trim((string) $sender));

    // Remove spaces, hyphens and other formatting characters.
    $sender = preg_replace('/[^A-Z0-9+]/', '', $sender);

    return $sender;
}