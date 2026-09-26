namespace Chameleon.Net.Profiles;

public interface IProfileRepository
{
    IReadOnlyCollection<string> Names { get; }

    ClientProfile Resolve(string name);

    bool TryResolve(string name, out ClientProfile? profile);

    void Register(ClientProfile profile);
}
