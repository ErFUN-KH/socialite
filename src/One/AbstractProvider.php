<?php

namespace Laravel\Socialite\One;

use Illuminate\Http\Request;
use Illuminate\Support\Str;
use InvalidArgumentException;
use League\OAuth1\Client\Server\Server;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Laravel\Socialite\Contracts\Provider as ProviderContract;

abstract class AbstractProvider implements ProviderContract
{
    /**
     * The HTTP request instance.
     *
     * @var Request
     */
    protected $request;

    /**
     * The OAuth server implementation.
     *
     * @var Server
     */
    protected $server;

    /**
     * Indicates if the session state should be utilized.
     *
     * @var bool
     */
    protected $stateless = false;

    /**
     * Create a new provider instance.
     *
     * @param  Request  $request
     * @param  Server  $server
     * @return void
     */
    public function __construct(Request $request, Server $server)
    {
        $this->server = $server;
        $this->request = $request;
    }

    /**
     * Redirect the user to the authentication page for the provider.
     *
     * @return RedirectResponse
     */
    public function redirect()
    {
        $state = null;
        if ($this->usesState()) {
            $this->request->session()->put(
                'oauth.temp', $temp = $this->server->getTemporaryCredentials()
            );
            return new RedirectResponse($this->server->getAuthorizationUrl($temp));
        } else {
            // Generate a temporary identifier for this user
            $tempId = str_random(40);
            // Add encrypted credentials to configured callback URL
            $callback = $this->server->getClientCredentials()->getCallbackUri();
            $this->server->getClientCredentials()->setCallbackUri(
                $callback.(strpos($callback, '?') !== false ? '&' : '?').http_build_query([
                    'tempId' => $tempId,
                ])
            );
            // Get the temporary credentials
            $temp = $this->server->getTemporaryCredentials();
            // Cache the credentials against the temporary identifier
            $this->app('cache')->put($this->getTempIdCacheKey($tempId), $temp, 1);
            // Redirect the user
            return new RedirectResponse($this->server->getAuthorizationUrl($temp));
        }
    }

    /**
     * Get the User instance for the authenticated user.
     *
     * @return \Laravel\Socialite\One\User
     */
    public function user()
    {
        if (! $this->hasNecessaryVerifier()) {
            throw new InvalidArgumentException('Invalid request. Missing OAuth verifier.');
        }

        $user = $this->server->getUserDetails($token = $this->getToken());

        $instance = (new User)->setRaw($user->extra)
                ->setToken($token->getIdentifier(), $token->getSecret());

        return $instance->map([
            'id' => $user->uid, 'nickname' => $user->nickname,
            'name' => $user->name, 'email' => $user->email, 'avatar' => $user->imageUrl,
        ]);
    }

    /**
     * Get the token credentials for the request.
     *
     * @return \League\OAuth1\Client\Credentials\TokenCredentials
     */
    protected function getToken()
    {
        $temp = $this->request->getSession()->get('oauth.temp');

        if (empty($temp)) {
            $temp = $this->app('cache')->get($this->getTempIdCacheKey($this->request->input('tempId')));
        }

        return $this->server->getTokenCredentials(
            $temp, $this->request->get('oauth_token'), $this->request->get('oauth_verifier')
        );
    }

    /**
     * Determine if the request has the necessary OAuth verifier.
     *
     * @return bool
     */
    protected function hasNecessaryVerifier()
    {
        return $this->request->has('oauth_token') && $this->request->has('oauth_verifier');
    }

    /**
     * Set the request instance.
     *
     * @param  Request  $request
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Determine if the provider is operating with state.
     *
     * @return bool
     */
    protected function usesState()
    {
        return ! $this->stateless;
    }

    /**
     * Determine if the provider is operating as stateless.
     *
     * @return bool
     */
    protected function isStateless()
    {
        return $this->stateless;
    }

    /**
     * Indicates that the provider should operate as stateless.
     *
     * @return $this
     */
    public function stateless()
    {
        $this->stateless = true;
        return $this;
    }

    /**
     * Get the string used for session state.
     *
     * @return string
     */
    protected function getState()
    {
        return Str::random(40);
    }

    /**
     * Get a cache key for temporary credentials.
     *
     * @param string $tempId
     * @return string
     */
    protected function getTempIdCacheKey($tempId)
    {
        return 'twitter-sign-in-temp:'.$tempId;
    }
}
