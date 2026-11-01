<?php
/**
 * Payment Verifier — API hardening helpers.
 */
if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('pv_api_error')) {
    function pv_api_error($code, $message, $status = 400, $data = array()) {
        $safe = array(
            'success' => false,
            'code' => sanitize_key($code),
            'message' => wp_strip_all_tags($message),
        );

        if (is_array($data)) {
            foreach ($data as $key => $value) {
                if (in_array($key, array('correlation_id', 'order_id', 'status'), true)) {
                    $safe[sanitize_key($key)] = is_scalar($value) ? sanitize_text_field((string) $value) : '';
                }
            }
        }

        return new WP_Error(
            $safe['code'],
            $safe['message'],
            array(
                'status' => absint($status),
                'pv_safe_response' => $safe,
            )
        );
    }
}

if (!function_exists('pv_api_correlation_id')) {
    function pv_api_correlation_id($request = null) {
        $id = '';

        // First preference: correlation ID supplied by the API client.
        if ($request instanceof WP_REST_Request) {
            $id = $request->get_header('X-PV-Correlation-ID');
        }

        // Fallback to the plugin's correlation-ID helper.
        if (!$id && function_exists('pv_request_correlation_id')) {
            $id = pv_request_correlation_id($request);
        }

        // Final fallback: generate a new correlation ID.
        if (!$id) {
            $id = wp_generate_uuid4();
        }

        // Correlation IDs are opaque identifiers.
        $id = substr(
            preg_replace('/[^A-Za-z0-9._:-]/', '', (string) $id),
            0,
            128
        );

        // Extremely defensive fallback in case sanitization removes everything.
        if (!$id) {
            $id = wp_generate_uuid4();
        }

        return $id;
    }
}

add_filter('rest_post_dispatch', function ($result, $server, $request) {
    if (strpos($request->get_route(), '/payment-verifier/') !== 0) {
        return $result;
    }

    $correlation_id = pv_api_correlation_id($request);

    if ($result instanceof WP_REST_Response) {
        $result->header('X-PV-Correlation-ID', $correlation_id);
    } elseif ($result instanceof WP_Error) {
        $error_data = $result->get_error_data();

        $status = 500;

        if (is_array($error_data) && isset($error_data['status'])) {
            $status = absint($error_data['status']);
        }

        $result->add_data(array(
            'status' => $status,
            'correlation_id' => $correlation_id,
        ));
    }

    return $result;
}, 10, 3);
