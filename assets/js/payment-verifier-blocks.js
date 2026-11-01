(function () {
    'use strict';

    if (
        !window.wc ||
        !window.wc.wcBlocksRegistry ||
        typeof window.wc.wcBlocksRegistry.registerPaymentMethod !== 'function'
    ) {
        console.error(
            'Payment Verifier: WooCommerce Blocks registry is not available.'
        );
        return;
    }

    if (!window.wp || !window.wp.element) {
        console.error('Payment Verifier: WordPress element package is not available.');
        return;
    }

    const { registerPaymentMethod } = window.wc.wcBlocksRegistry;
    const { createElement } = window.wp.element;

    const getSettings = (key) => {
        if (
            window.wc.wcSettings &&
            typeof window.wc.wcSettings.getSetting === 'function'
        ) {
            return window.wc.wcSettings.getSetting(key, {});
        }
        return {};
    };

    const registerProvider = (provider, fallbackLabel, fallbackDescription) => {
        const settings = getSettings('payment_verifier_' + provider + '_data');
        const label = settings.title || fallbackLabel;
        const description = settings.description || fallbackDescription;

        const PaymentContent = () => createElement(
            'div',
            { className: 'payment-verifier-content' },
            description
        );

        registerPaymentMethod({
            name: 'payment_verifier_' + provider,
            label: label,
            content: createElement(PaymentContent),
            edit: createElement(PaymentContent),
            ariaLabel: label,
            canMakePayment: () => true,
            supports: {
                features: ['products']
            }
        });
    };

    registerProvider(
        'bkash',
        'bKash',
        'Pay the exact order amount using bKash. Payment will be verified automatically.'
    );

    registerProvider(
        'nagad',
        'Nagad',
        'Pay the exact order amount using Nagad. Payment will be verified automatically.'
    );
})();
