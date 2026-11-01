<?php
if (!defined('ABSPATH')) exit;

/**
 * Phase 9:
 * Bind a customer's submitted provider + transaction ID to the WooCommerce order.
 *
 * The checkout UI is intentionally minimal. A production release should use
 * a dedicated payment gateway/payment method and provider-specific validation.
 */

add_action('woocommerce_checkout_create_order', function ($order, $data) {
    if (!isset($_POST['pv_provider'], $_POST['pv_transaction_id'])) {
        return;
    }

    $provider = sanitize_key(wp_unslash($_POST['pv_provider']));
    $txn = sanitize_text_field(wp_unslash($_POST['pv_transaction_id']));

    if (!in_array($provider, array('bkash', 'nagad'), true)) {
        return;
    }

    if ($txn === '') {
        return;
    }

    $order->update_meta_data('_pv_provider', $provider);
    $order->update_meta_data('_pv_transaction_id', $txn);
}, 10, 2);
