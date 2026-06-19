add_action('wp_enqueue_scripts', function () {
    wp_register_script('legal-form-js', false);
    wp_enqueue_script('legal-form-js');

    wp_localize_script('legal-form-js', 'legalFormAjax', [
        'ajax_url' => admin_url('admin-ajax.php'),
        'nonce'    => wp_create_nonce('legal_form_nonce'),
    ]);
});

add_action('wp_ajax_send_legal_form', 'send_legal_form');
add_action('wp_ajax_nopriv_send_legal_form', 'send_legal_form');

function send_legal_form() {
    if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'legal_form_nonce')) {
        wp_send_json_error('Solicitud no válida.');
    }

    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $rate_key = 'legal_form_rate_' . md5($ip);
    $attempts = (int) get_transient($rate_key);

    if ($attempts >= 3) {
        wp_send_json_error('Has realizado demasiados envíos. Inténtalo de nuevo más tarde.');
    }

    set_transient($rate_key, $attempts + 1, 15 * MINUTE_IN_SECONDS);

    if (!empty($_POST['website'])) {
        wp_send_json_error('Spam detectado.');
    }

    $area       = sanitize_text_field($_POST['area'] ?? '');
    $nombre     = sanitize_text_field($_POST['nombre'] ?? '');
    $email      = sanitize_email($_POST['email'] ?? '');
    $telefono   = sanitize_text_field($_POST['telefono'] ?? '');
    $caso       = sanitize_textarea_field($_POST['caso'] ?? '');
    $privacidad = isset($_POST['privacidad']);

    if (!$privacidad) {
        wp_send_json_error('Debes aceptar la política de privacidad.');
    }

    if (empty($area) || empty($nombre) || empty($email) || empty($caso)) {
        wp_send_json_error('Faltan campos obligatorios.');
    }

    if (!is_email($email)) {
        wp_send_json_error('El correo no es válido.');
    }

$to = [
    'nuria.gonzalez@sib.es',
    'nuria.sib.es@gmail.com',
];
	$subject = 'Nueva consulta jurídica desde la web';

    $body = "Nueva consulta recibida:\n\n";
    $body .= "Área: $area\n";
    $body .= "Nombre: $nombre\n";
    $body .= "Email: $email\n";
    $body .= "Teléfono: $telefono\n";
    $body .= "Acepta privacidad: Sí\n\n";
    $body .= "Caso:\n$caso\n";

    $headers = [
        'Content-Type: text/plain; charset=UTF-8',
        'Reply-To: ' . $nombre . ' <' . $email . '>',
    ];

    $sent = wp_mail($to, $subject, $body, $headers);

    if ($sent) {
        wp_send_json_success('Consulta enviada correctamente.');
    } else {
        wp_send_json_error('No se ha podido enviar el mensaje.');
    }
}
