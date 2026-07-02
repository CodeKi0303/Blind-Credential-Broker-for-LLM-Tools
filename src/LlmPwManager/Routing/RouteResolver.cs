using LlmPwManager.Config;

namespace LlmPwManager.Routing;

internal sealed class RouteResolver(AppConfig config)
{
    public ResolvedRoute Resolve(string routeId)
    {
        var route = config.Routes.FirstOrDefault(r => r.Id.Equals(routeId, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"Unknown route: {routeId}");

        var chain = route.SshChain.Select(id =>
            config.SshTargets.FirstOrDefault(t => t.Id.Equals(id, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"Route {routeId} references unknown SSH target: {id}"))
            .ToList();

        if (chain.Count == 0)
        {
            throw new InvalidOperationException($"Route {routeId} has an empty SSH chain.");
        }

        return new ResolvedRoute(route.Id, chain);
    }
}

internal sealed record ResolvedRoute(string Id, IReadOnlyList<SshTarget> SshChain);
