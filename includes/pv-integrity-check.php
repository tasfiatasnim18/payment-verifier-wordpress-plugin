<?php
/**
 * Payment Verifier — Database / WooCommerce integrity checks.
 *
 * Read-only diagnostics. It does not mutate orders or payment records.
 */
if (!defined('ABSPATH')) {
    exit;
}

function pv_run_integrity_checks() {
    global $wpdb;

    $results = array();

    $tables = array(
        'audit'       => $wpdb->prefix . 'pv_audit_log',
        'devices'     => $wpdb->prefix . 'pv_devices',
        'stores'      => $wpdb->prefix . 'pv_stores',
        'device_store'=> $wpdb->prefix . 'pv_device_stores',
    );

    foreach ($tables as $key => $table) {
        $results['table_' . $key] =
            ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) === $table);
    }

    $results['woocommerce'] = class_exists('WooCommerce');
    $results['wc_order_api'] = class_exists('WC_Order');

    // The exact schema can vary by release, so verify required columns only
    // when the table exists.
    $required = array(
        'audit' => array('id'),
        'devices' => array('id'),
        'stores' => array('id'),
        'device_store' => array('id'),
    );

    foreach ($required as $key => $columns) {
        $table = $tables[$key];
        if (empty($results['table_' . $key])) {
            continue;
        }

        $existing = $wpdb->get_col("DESCRIBE {$table}", 0);
        foreach ($columns as $column) {
            $results[$key . '_column_' . $column] = in_array($column, $existing, true);
        }
    }

    return $results;
}
