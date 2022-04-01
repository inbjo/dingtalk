<?php

/*
 * This file is part of the mingyoung/dingtalk.
 *
 * (c) 张铭阳 <mingyoungcheung@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace EasyDingTalk\Auth;

use EasyDingTalk\Kernel\Http\Client;
use Symfony\Component\HttpFoundation\RedirectResponse;

class OAuthClient extends Client
{
    use HasStateParameter;

    /**
     * @var array
     */
    protected $credential;

    /**
     * @var bool
     */
    protected $withQrConnect = false;

    /**
     * @var string|null
     */
    protected $redirect;

    /**
     * @param string $name
     *
     * @return $this
     */
    public function use($name)
    {
        $this->credential = $this->app['config']->get('oauth')[$name];

        return $this;
    }

    /**
     * @return string
     */
    public function getRedirectUrl()
    {
        return $this->redirect ?: $this->credential['redirect'];
    }

    /**
     * @param string $url
     *
     * @return $this
     */
    public function setRedirectUrl($url)
    {
        $this->redirect = $url;

        return $this;
    }

    /**
     * @return $this
     */
    public function withQrConnect()
    {
        $this->withQrConnect = true;

        return $this;
    }

    /**
     * Redirect to the authentication page.
     *
     * @param string|null $url
     *
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function redirect($url = null)
    {
        $query = [
            'appid' => $this->credential['client_id'],
            'response_type' => 'code',
            'scope' => $this->credential['scope'],
            'state' => $this->makeState(),
            'redirect_uri' => $url ?: $this->getRedirectUrl(),
        ];

        return new RedirectResponse(
            sprintf('https://oapi.dingtalk.com/connect/%s?%s', $this->withQrConnect ? 'qrconnect' : 'oauth2/sns_authorize', http_build_query(array_filter($query)))
        );
    }

    /**
     * @return array
     *
     * @throws \EasyDingTalk\Auth\InvalidStateException
     */
    public function user(bool $isJsLogin = false)
    {
        if (!$isJsLogin && !$this->hasValidState($this->app['request']->get('state'))) {
            throw new InvalidStateException('state invalid');
        }

        $data = [
            'tmp_auth_code' => $this->app['request']->get('code'),
        ];

        $query = [
            'accessKey' => $this->credential['client_id'],
            'timestamp' => $timestamp = (int) microtime(true) * 1000,
            'signature' => $this->signature($timestamp),
        ];

        return $this->postJson('sns/getuserinfo_bycode', $data, $query);
    }
    
     /**
     * JSON request.
     *
     * @param string $url
     * @param string|array $data
     * @param array $query
     *
     * @return \Psr\Http\Message\ResponseInterface|\Overtrue\Http\Support\Collection|array|object|string
     * @throws \GuzzleHttp\Exception\GuzzleException
     *
     */
    public function postJson(string $url, array $data = [], array $query = [])
    {
        return $this->request($url, 'POST', ['query' => $query, 'json' => $data]);
    }

    /**
     * 计算签名
     *
     * @param int $timestamp
     *
     * @return string
     */
    public function signature($timestamp)
    {
        return base64_encode(hash_hmac('sha256', $timestamp, $this->credential['client_secret'], true));
    }
}
