namespace Chameleon.Net.Profiles;

public interface IProfileSerializer
{
    ClientProfile Read(Stream source);

    void Write(ClientProfile profile, Stream destination);
}
