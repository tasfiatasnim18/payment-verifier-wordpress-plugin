<?php
if (!defined('ABSPATH')) exit;

/**
 * Register the two Payment Verifier gateways separately.
 *
 * Each gateway has its own WooCommerce gateway ID and settings namespace.
 * The verification engine continues to use the existing _pv_provider order
 * meta, so no Android/API verification logic needs to change.
 */
add_filter('woocommerce_payment_gateways', function ($methods) {
    $methods[] = 'WC_Gateway_Payment_Verifier_Bkash';
    $methods[] = 'WC_Gateway_Payment_Verifier_Nagad';
    return $methods;
});

add_action('plugins_loaded', function () {
    if (!class_exists('WC_Payment_Gateway')) return;

    /**
     * One shared implementation for the provider-specific gateways.
     */
    class PV_WC_Gateway_Payment_Verifier extends WC_Payment_Gateway {

        /** @var string bkash|nagad */
        protected $pv_provider = '';

        public function __construct($provider) {
            $this->pv_provider = sanitize_key($provider);

            $this->id = 'payment_verifier_' . $this->pv_provider;
            $this->icon = '';
            $this->has_fields = true;
            $this->method_title = $this->pv_provider === 'bkash' ? 'bKash' : 'Nagad';
            $this->method_description = sprintf(
                'Automatic %s payment verification using vendor SMS.',
                $this->pv_provider === 'bkash' ? 'bKash' : 'Nagad'
            );

            $this->init_form_fields();
            $this->init_settings();

            $default_title = $this->pv_provider === 'bkash' ? 'bKash' : 'Nagad';
            $default_description = sprintf(
                'Pay the exact order amount using %s. Payment will be verified automatically.',
                $default_title
            );

            $this->title = $this->get_option('title', $default_title);
            $this->description = $this->get_option('description', $default_description);

            add_action(
                'woocommerce_update_options_payment_gateways_' . $this->id,
                array($this, 'process_admin_options')
            );
        }

        public function init_form_fields() {
            $provider_label = $this->pv_provider === 'bkash' ? 'bKash' : 'Nagad';

            $this->form_fields = array(
                'enabled' => array(
                    'title'   => 'Enable/Disable',
                    'type'    => 'checkbox',
                    'label'   => 'Enable ' . $provider_label,
                    'default' => 'yes',
                ),

                'title' => array(
                    'title'    => 'Title',
                    'type'     => 'text',
                    'default'  => $provider_label,
                    'desc_tip' => true,
                ),

                'description' => array(
                    'title'   => 'Description',
                    'type'    => 'textarea',
                    'default' => sprintf(
                        'Pay the exact order amount using %s. Payment will be verified automatically.',
                        $provider_label
                    ),
                ),

                'instructions' => array(
                    'title'   => 'Payment Instructions',
                    'type'    => 'textarea',
                    'default' => sprintf(
                        'Send the exact order total using %s to the merchant number. Your payment will be verified automatically after the merchant receives the payment SMS.',
                        $provider_label
                    ),
                ),
            );
        }

        public function payment_fields() {
            if ($this->description) {
                echo wpautop(wp_kses_post($this->description));
            }

            echo '<div class="pv-checkout-fields">';
            echo '<p><strong>Payment Instructions</strong></p>';
            echo '<p>' . nl2br(esc_html($this->get_option('instructions'))) . '</p>';
            echo '</div>';
        }

        public function validate_fields() {
            // Provider is fixed by this gateway ID. There is no provider
            // dropdown and therefore nothing for the customer to select.
            return true;
        }

        public function process_payment($order_id) {

            $order = wc_get_order($order_id);

            if (!$order) {
                wc_add_notice(
                    'Unable to create the payment order.',
                    'error'
                );

                return array(
                    'result' => 'failure',
                );
            }
            $provider = $this->pv_provider;

            if (!in_array($provider, array('bkash', 'nagad'), true)) {
                wc_add_notice('Invalid payment provider.', 'error');
                return array('result' => 'failure');
            }

            function pv_generate_payment_reference() {
                $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

                do {
                    $reference = 'PV-';

                    for ($i = 0; $i < 6; $i++) {
                        $reference .= $alphabet[random_int(0, strlen($alphabet) - 1)];
                    }

                    $existing = wc_get_orders([
                        'limit'      => 1,
                        'meta_key'   => '_pv_payment_reference',
                        'meta_value' => $reference,
                        'return'     => 'ids',
                    ]);

                } while (!empty($existing));

                return $reference;
            }

            $reference = pv_generate_payment_reference();

            // Save the fixed provider selected by the customer through the
            // gateway itself. Android verification continues to read this
            // existing order meta key.
            $order->update_meta_data('_pv_provider', $provider);
            $order->update_meta_data('_pv_transaction_id', '');
            $order->update_meta_data('_pv_payment_reference', $reference);
            $order->update_meta_data('_pv_verification_status', 'pending');
            $order->update_meta_data('_pv_payment_intent_created_at', time());
            $order->save();

            $order->update_status(
                'on-hold',
                sprintf(
                    'Awaiting automatic %s payment verification. Payment Reference: %s.',
                    strtoupper($provider),
                    $reference
                )
            );

            wc_reduce_stock_levels($order_id);

            if (WC()->cart) {
                WC()->cart->empty_cart();
            }

            return array(
                'result'   => 'success',
                'redirect' => $this->get_return_url($order),
            );
        }
    }

    /**
     * Backward-compatible class name retained for existing source tests and
     * integrations. It is intentionally not registered as a gateway.
     */
    class WC_Gateway_Payment_Verifier extends PV_WC_Gateway_Payment_Verifier {
        public function __construct() {
            parent::__construct('bkash');
        }
    }

    class WC_Gateway_Payment_Verifier_Bkash extends PV_WC_Gateway_Payment_Verifier {
        public function __construct() {
            parent::__construct('bkash');
        }
    }

    class WC_Gateway_Payment_Verifier_Nagad extends PV_WC_Gateway_Payment_Verifier {
        public function __construct() {
            parent::__construct('nagad');
        }
    }
});

/**
 * Migrate the old combined gateway settings to the new provider-specific
 * settings once. Existing settings are never overwritten.
 */
add_action('plugins_loaded', function () {
    if (!function_exists('get_option') || !function_exists('add_option')) return;

    $legacy = get_option('woocommerce_payment_verifier_settings', array());
    if (!is_array($legacy) || !$legacy) return;

    $defaults = array(
        'enabled'      => isset($legacy['enabled']) ? $legacy['enabled'] : 'yes',
        'description'  => isset($legacy['description']) ? $legacy['description'] : '',
        'instructions' => isset($legacy['instructions']) ? $legacy['instructions'] : '',
    );

    $providers = array(
        'bkash' => array(
            'title' => 'bKash',
            'description' => 'Pay the exact order amount using bKash. Payment will be verified automatically.',
            'instructions' => 'Send the exact order total using bKash to the merchant number. Your payment will be verified automatically after the merchant receives the payment SMS.',
        ),
        'nagad' => array(
            'title' => 'Nagad',
            'description' => 'Pay the exact order amount using Nagad. Payment will be verified automatically.',
            'instructions' => 'Send the exact order total using Nagad to the merchant number. Your payment will be verified automatically after the merchant receives the payment SMS.',
        ),
    );

    foreach ($providers as $provider => $provider_defaults) {
        $option_name = 'woocommerce_payment_verifier_' . $provider . '_settings';

        if (get_option($option_name, null) !== null) {
            continue;
        }

        add_option($option_name, array(
            'enabled'      => $defaults['enabled'],
            'title'        => $provider_defaults['title'],
            'description'  => $provider_defaults['description'],
            'instructions' => $provider_defaults['instructions'],
        ));
    }
}, 20);
