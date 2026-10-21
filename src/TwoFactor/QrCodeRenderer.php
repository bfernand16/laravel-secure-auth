<?php

namespace SecureAuth\TwoFactor;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;

/** Renders the otpauth URL as an SVG QR code on the server: the secret never goes to a third-party QR service. */
class QrCodeRenderer
{
    public function svg(string $content): string
    {
        $size = (int) config('secure-auth.two_factor.qr_size', 200);
        $writer = new Writer(new ImageRenderer(new RendererStyle($size, 1), new SvgImageBackEnd));

        return trim((string) preg_replace('/^<\?xml.*?\?>\s*/', '', $writer->writeString($content)));
    }
}
