<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * Protects API routes called server-to-server by partner systems (e.g. cvchd7.com).
 *
 * Each check is enforced only when its .env value is set, so it can be rolled out
 * without breaking the partner before they start sending the key:
 *   PARTNER_API_KEY=long-random-string        -> requires header "X-API-KEY: <key>"
 *   PARTNER_ALLOWED_IPS=1.2.3.4,5.6.7.8       -> only these client IPs may call
 */
class VerifyPartnerApi
{
    public function handle(Request $request, Closure $next)
    {
        $allowedIps = array_filter(array_map('trim', explode(',', (string) config('services.partner_api.allowed_ips'))));
        if ($allowedIps && !in_array($request->ip(), $allowedIps, true)) {
            return response()->json(['code' => 403, 'message' => 'Forbidden'], 403);
        }

        $key = (string) config('services.partner_api.key');
        if ($key !== '' && !hash_equals($key, (string) $request->header('X-API-KEY'))) {
            return response()->json(['code' => 401, 'message' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
