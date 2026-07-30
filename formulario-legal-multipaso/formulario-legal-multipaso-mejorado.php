add_action('wp_enqueue_scripts', function () {
    wp_register_script('legal-form-js', false);
    wp_enqueue_script('legal-form-js');

    // Token de un solo uso + marca de tiempo, independiente del nonce de WP.
    // Sirve para detectar envíos "instantáneos" (bots) y para impedir
    // que el mismo formulario cargado una vez se reenvíe múltiples veces.
    $form_token = wp_generate_password(32, false);
    set_transient('legal_form_token_' . $form_token, time(), 30 * MINUTE_IN_SECONDS);

    wp_localize_script('legal-form-js', 'legalFormAjax', [
        'ajax_url'   => admin_url('admin-ajax.php'),
        'nonce'      => wp_create_nonce('legal_form_nonce'),
        'form_token' => $form_token,
    ]);
});

add_action('wp_ajax_send_legal_form', 'send_legal_form');
add_action('wp_ajax_nopriv_send_legal_form', 'send_legal_form');

/**
 * Registra un intento bloqueado y, si se acumulan varios en poco tiempo,
 * envía UNA sola alerta por email (con cooldown de 1h para no generar
 * spam hacia ti mismo si hay un ataque sostenido).
 */
function legal_form_log_abuse($reason, $ip) {
    error_log(sprintf('[legal-form] Bloqueado (%s) IP=%s', $reason, $ip));

    $count_key = 'legal_form_abuse_count';
    $count = (int) get_transient($count_key);
    $count++;
    set_transient($count_key, $count, 10 * MINUTE_IN_SECONDS);

    if ($count >= 5 && !get_transient('legal_form_abuse_alert_sent')) {
        set_transient('legal_form_abuse_alert_sent', 1, HOUR_IN_SECONDS);
        wp_mail(
            'MAIL@MAIL.COM',
            'Aviso: posible abuso en formulario de contacto',
            "Se han bloqueado {$count} intentos de envío sospechosos en los últimos 10 minutos.\n" .
            "Último motivo: {$reason}\nÚltima IP: {$ip}\n\n" .
            "Revisa el registro de errores de PHP en Plesk para más detalle."
        );
    }
}

function send_legal_form() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

    // 1. Comprobación de origen: la petición debe venir de tu propio dominio.
    $referer = $_SERVER['HTTP_REFERER'] ?? '';
    $site_host = wp_parse_url(home_url(), PHP_URL_HOST);
    if (empty($referer) || wp_parse_url($referer, PHP_URL_HOST) !== $site_host) {
        legal_form_log_abuse('origen no válido', $ip);
        wp_send_json_error('Solicitud no válida.');
    }

    // 2. Nonce estándar de WordPress (protección CSRF).
    if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'legal_form_nonce')) {
        legal_form_log_abuse('nonce inválido', $ip);
        wp_send_json_error('Solicitud no válida.');
    }

    // 3. Token de un solo uso + tiempo mínimo de relleno.
    //    Se exige que hayan pasado al menos 3 segundos desde que se cargó
    //    el formulario, y el token se invalida tras el primer uso.
    $form_token = sanitize_text_field($_POST['form_token'] ?? '');
    $token_key  = 'legal_form_token_' . $form_token;
    $issued_at  = get_transient($token_key);

    if (empty($form_token) || $issued_at === false) {
        legal_form_log_abuse('token ausente o ya usado', $ip);
        wp_send_json_error('La sesión del formulario ha caducado. Recarga la página e inténtalo de nuevo.');
    }

    delete_transient($token_key); // de un solo uso, se use válidamente o no

    if ((time() - (int) $issued_at) < 3) {
        legal_form_log_abuse('envío demasiado rápido (bot probable)', $ip);
        wp_send_json_error('No se ha podido procesar el envío. Inténtalo de nuevo.');
    }

    // 4. Límite por IP (como ya tenías).
    $rate_key = 'legal_form_rate_' . md5($ip);
    $attempts = (int) get_transient($rate_key);

    if ($attempts >= 3) {
        legal_form_log_abuse('límite por IP superado', $ip);
        wp_send_json_error('Has realizado demasiados envíos. Inténtalo de nuevo más tarde.');
    }

    set_transient($rate_key, $attempts + 1, 15 * MINUTE_IN_SECONDS);

    // 5. Límite global (independiente de la IP), para frenar ataques
    //    distribuidos entre muchas IPs distintas.
    $global_key = 'legal_form_global_rate';
    $global_attempts = (int) get_transient($global_key);

    if ($global_attempts >= 20) {
        legal_form_log_abuse('límite global superado', $ip);
        wp_send_json_error('El formulario no está disponible temporalmente. Inténtalo de nuevo en unos minutos.');
    }

    set_transient($global_key, $global_attempts + 1, 10 * MINUTE_IN_SECONDS);

    // 6. Honeypot.
    if (!empty($_POST['website'])) {
        legal_form_log_abuse('honeypot activado', $ip);
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
        'MAIL@MAIL.COM',
        'MAIL@MAIL.COM',
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
