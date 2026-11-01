<?php
/**
 * Payment Verifier — WooCommerce order transition guard.
 *
 * The guard is intentionally conservative. It does not decide whether a
 * payment is valid; it only prevents callers from completing an order unless
 * they explicitly provide a verified payment result.
 */
if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('pv_complete_verified_order')) {
    function pv_complete_verified_order($order_id, $verification = array()) {
        if (!class_exists('WC_Order')) {
            return new WP_Error('woocommerce_unavailable', 'WooCommerce is unavailable.');
        }

        $order = wc_get_order(absint($order_id));
        if (!$order) {
            return new WP_Error('order_not_found', 'Order not found.');
        }

        if (!is_array($verification) || empty($verification['verified'])) {
            return new WP_Error('payment_not_verified', 'Order cannot be completed without a verified payment result.');
        }

        $required = array('transaction_id', 'provider', 'amount');
        foreach ($required as $field) {
            if (!isset($verification[$field]) || $verification[$field] === '') {
                return new WP_Error('verification_incomplete', 'Verified payment data is incomplete.');
            }
        }

        // Never regress a terminal state.
        $current = $order->get_status();
        if (in_array($current, array('completed', 'cancelled', 'refunded', 'failed'), true)) {
            if ($current === 'completed') {
                return $order;
            }
            return new WP_Error('terminal_order_state', 'Order is already in a terminal state.');
        }

        $order->update_meta_data('_pv_verified_transaction_id',
            sanitize_text_field((string) $verification['transaction_id']));
        $order->update_meta_data('_pv_verified_provider',
            sanitize_key($verification['provider']));
        $order->update_meta_data('_pv_verified_amount',
            wc_format_decimal($verification['amount']));
        $order->update_meta_data('_pv_payment_verified_at', current_time('mysql'));

        $order->payment_complete(
            sanitize_text_field((string) $verification['transaction_id'])
        );

        $order->save();

        return $order;
    }
}
