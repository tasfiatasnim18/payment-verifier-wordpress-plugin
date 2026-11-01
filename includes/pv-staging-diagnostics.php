<?php
/**
 * Payment Verifier — Staging Diagnostics
 *
 * Read-only operational diagnostics. No credentials or payment data are exposed.
 */

if (!defined('ABSPATH')) {
    exit;
}

function pv_render_staging_diagnostics() {
    if (!current_user_can('manage_woocommerce')) {
        wp_die(esc_html__('You do not have permission to view Payment Verifier diagnostics.', 'payment-verifier'));
    }

    global $wpdb;

    $checks = array();

    $checks['WordPress'] = defined('ABSPATH');
    $checks['WooCommerce'] = class_exists('WooCommerce');

    $audit_table = $wpdb->prefix . 'pv_audit_log';
    $devices_table = $wpdb->prefix . 'pv_devices';
    $stores_table = $wpdb->prefix . 'pv_stores';
    $device_store_table = $wpdb->prefix . 'pv_device_stores';

    $tables = array(
        'Audit log' => $audit_table,
        'Devices' => $devices_table,
        'Stores' => $stores_table,
        'Device/store scope' => $device_store_table,
    );

    foreach ($tables as $label => $table) {
        $checks[$label] = ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) === $table);
    }

    $site_url = site_url();
    $https = (wp_parse_url($site_url, PHP_URL_SCHEME) === 'https');
    $checks['HTTPS'] = $https;

    $correlation_function = function_exists('pv_request_correlation_id');
    $audit_function = function_exists('pv_audit');
    $checks['Correlation ID support'] = $correlation_function;
    $checks['Audit support'] = $audit_function;

    ?>
    <div class="wrap">
        <h1><?php echo esc_html__('Payment Verifier — Staging Diagnostics', 'payment-verifier'); ?></h1>
        <p><?php echo esc_html__('Read-only health checks for staging/deployment verification. Secrets and payment credentials are never displayed.', 'payment-verifier'); ?></p>

        <table class="widefat striped" style="max-width:900px;">
            <thead>
                <tr>
                    <th><?php echo esc_html__('Check', 'payment-verifier'); ?></th>
                    <th><?php echo esc_html__('Status', 'payment-verifier'); ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($checks as $label => $passed): ?>
                <tr>
                    <td><?php echo esc_html($label); ?></td>
                    <td>
                        <strong style="<?php echo $passed ? 'color:#008a20;' : 'color:#b32d2e;'; ?>">
                            <?php echo $passed ? esc_html__('PASS', 'payment-verifier') : esc_html__('FAIL', 'payment-verifier'); ?>
                        </strong>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>

        <h2><?php echo esc_html__('Environment', 'payment-verifier'); ?></h2>
        <p><strong>WordPress:</strong> <?php echo esc_html(get_bloginfo('version')); ?></p>
        <p><strong>PHP:</strong> <?php echo esc_html(PHP_VERSION); ?></p>
        <p><strong>Site:</strong> <?php echo esc_html($site_url); ?></p>
        <p><strong>HTTPS:</strong> <?php echo $https ? esc_html__('Enabled', 'payment-verifier') : esc_html__('Disabled', 'payment-verifier'); ?></p>

        <?php if (!$https): ?>
            <div class="notice notice-warning inline">
                <p><?php echo esc_html__('HTTPS is required before using real device credentials or payment traffic.', 'payment-verifier'); ?></p>
            </div>
        <?php endif; ?>
    </div>
    <?php
}
