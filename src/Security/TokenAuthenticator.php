<?php

namespace App\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

class TokenAuthenticator extends AbstractAuthenticator
{
    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization');
    }

    public function authenticate(Request $request): SelfValidatingPassport
    {
        $authHeader = $request->headers->get('Authorization');
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            throw new AuthenticationException('No Bearer token provided');
        }

        $token = substr($authHeader, 7);

        if ($token === 'testAdmin') {
            return new SelfValidatingPassport(
                new UserBadge('admin', fn(string $id): UserInterface => new InMemoryUser('admin', null, ['ROLE_ADMIN', 'ROLE_USER']))
            );
        }

        if ($token === 'testUser') {
            return new SelfValidatingPassport(
                new UserBadge('user', fn(string $id): UserInterface => new InMemoryUser('user', null, ['ROLE_USER']))
            );
        }

        throw new AuthenticationException('Invalid API Token');
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?JsonResponse
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?JsonResponse
    {
        return new JsonResponse(['error' => 'Unauthorized', 'message' => $exception->getMessage()], 401);
    }
}
