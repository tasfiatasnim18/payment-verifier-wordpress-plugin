<?php

use Automattic\WooCommerce\Blocks\Payments\Integrations\AbstractPaymentMethodType;

if (!defined('ABSPATH')) exit;

/**
 * Shared Checkout Blocks integration for provider-specific gateways.
 */
class PV_Blocks_Payment_Method extends AbstractPaymentMethodType {

    protected $name = '';
    protected $provider = '';
    protected $settings = array();
    protected $script_handle = 'payment-verifier-blocks';

    public function __construct($provider) {
        $this->provider = sanitize_key($provider);
        $this->name = 'payment_verifier_' . $this->provider;
    }

    public function initialize() {
        $this->settings = get_option(
            'woocommerce_payment_verifier_' . $this->provider . '_settings',
            array()
        );

        error_log(
            'PV BLOCKS initialize ' . strtoupper($this->provider) . ': ' .
            print_r($this->settings, true)
        );
    }

    public function is_active() {
        $enabled = isset($this->settings['enabled'])
            ? $this->settings['enabled']
            : 'no';

        $active = ($enabled === 'yes');

        error_log(
            'PV BLOCKS is_active ' . strtoupper($this->provider) . ': ' .
            ($active ? 'YES' : 'NO')
        );

        return $active;
    }

    public function get_payment_method_script_handles() {
        return array($this->script_handle);
    }

    public function get_payment_method_data() {
        $label = $this->provider === 'bkash' ? 'bKash' : 'Nagad';

        return array(
            'title' => isset($this->settings['title']) && $this->settings['title'] !== ''
                ? $this->settings['title']
                : $label,

            'description' => isset($this->settings['description']) && $this->settings['description'] !== ''
                ? $this->settings['description']
                : 'Pay the exact order amount using ' . $label . '. Payment will be verified automatically.',

            'supports' => array(
                'products',
            ),
        );
    }
}

class PV_Blocks_Payment_Method_Bkash extends PV_Blocks_Payment_Method {
    public function __construct() {
        parent::__construct('bkash');
    }
}

class PV_Blocks_Payment_Method_Nagad extends PV_Blocks_Payment_Method {
    public function __construct() {
        parent::__construct('nagad');
    }
}
