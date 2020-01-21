using UnityEngine;
using System.Linq;

public class ARC4AttackTest : MonoBehaviour
{
    // Start is called before the first frame update
    void Start()
    {
        var dict = ARC4Attack.Attack(System.Text.Encoding.UTF8.GetBytes("this_is_a_message"));
        var result = dict.OrderByDescending(e => e.Value).Take(5);

        foreach (var kvp in result)
        {
            Debug.LogFormat($"{System.Text.Encoding.UTF8.GetString(new byte[] { kvp.Key })}: {kvp.Value}");
        }
    }
}
