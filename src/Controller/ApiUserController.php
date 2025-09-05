<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;

#[Route('/v1/api/users')]
final class ApiUserController extends AbstractController
{
    private EntityManagerInterface $em;
    private ValidatorInterface $validator;

    public function __construct(EntityManagerInterface $em, ValidatorInterface $validator)
    {
        $this->em = $em;
        $this->validator = $validator;
    }

    private function getToken(Request $request): ?string
    {
        $authHeader = $request->headers->get('Authorization');
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return null;
        }
        return substr($authHeader, 7);
    }

    private function checkToken(?string $token, array $allowed): ?JsonResponse
    {
        if (!$token) {
            return $this->json([
                'error' => 'Unauthorized',
                'message' => 'No Bearer token provided'
            ], 401);
        }

        if (!in_array($token, $allowed)) {
            return $this->json(['error' => 'Unauthorized'], 401);
        }

        return null;
    }

    private function validateUser(User $user): ?JsonResponse
    {
        $errors = $this->validator->validate($user);
        if ($errors->count() > 0) {
            $messages = [];
            foreach ($errors as $error) {
                $messages[] = $error->getPropertyPath() . ': ' . $error->getMessage();
            }
            return $this->json(['errors' => $messages], 400);
        }
        return null;
    }

    private function serializeUser(User $user): array
    {
        return [
            'id' => $user->getId(),
            'login' => $user->getLogin(),
            'phone' => $user->getPhone(),
            'pass' => $user->getPass(),
        ];
    }

    #[Route('', methods: ['GET'])]
    public function list(Request $request): JsonResponse
    {
        $token = $this->getToken($request);
        if ($resp = $this->checkToken($token, ['testAdmin', 'testUser'])) return $resp;

        $repo = $this->em->getRepository(User::class);
        $users = $token === 'testAdmin'
            ? $repo->findAll()
            : $repo->findBy(['login' => 'user']);

        $data = array_map(fn(User $u) => $this->serializeUser($u), $users);
        return $this->json($data);
    }

    #[Route('', methods: ['POST'])]
    public function create(Request $request): JsonResponse
    {
        $token = $this->getToken($request);
        if ($resp = $this->checkToken($token, ['testAdmin', 'testUser'])) return $resp;

        $data = json_decode($request->getContent(), true) ?? [];
        $user = new User();
        $user->setLogin($data['login'] ?? '');
        $user->setPhone($data['phone'] ?? '');
        $user->setPass($data['pass'] ?? '');

        if ($resp = $this->validateUser($user)) return $resp;

        try {
            $this->em->persist($user);
            $this->em->flush();
        } catch (UniqueConstraintViolationException) {
            return $this->json([
                'error' => 'Conflict',
                'message' => 'User with this login and pass already exists.'
            ], 409);
        }

        return $this->json($this->serializeUser($user), 201);
    }

    #[Route('/{id}', methods: ['PUT'])]
    public function update(Request $request, int $id): JsonResponse
    {
        $token = $this->getToken($request);
        if ($resp = $this->checkToken($token, ['testAdmin', 'testUser'])) return $resp;

        $user = $this->em->getRepository(User::class)->find($id);
        if (!$user) return $this->json(['error' => 'User not found'], 404);

        if ($token === 'testUser' && $user->getLogin() !== 'user') {
            return $this->json(['error' => 'Forbidden'], 403);
        }

        $data = json_decode($request->getContent(), true) ?? [];
        $user->setLogin($data['login'] ?? $user->getLogin());
        $user->setPhone($data['phone'] ?? $user->getPhone());
        $user->setPass($data['pass'] ?? $user->getPass());

        if ($resp = $this->validateUser($user)) return $resp;

        try {
            $this->em->flush();
        } catch (UniqueConstraintViolationException) {
            return $this->json([
                'error' => 'Conflict',
                'message' => 'User with this login and pass already exists.'
            ], 409);
        }

        return $this->json($this->serializeUser($user));
    }

    #[Route('/{id}', methods: ['DELETE'])]
    public function delete(Request $request, int $id): JsonResponse
    {
        $token = $this->getToken($request);
        if ($resp = $this->checkToken($token, ['testAdmin'])) return $resp;

        $user = $this->em->getRepository(User::class)->find($id);
        if (!$user) return $this->json(['error' => 'User not found'], 404);

        $this->em->remove($user);
        $this->em->flush();

        return $this->json(['status' => 'deleted']);
    }
}
