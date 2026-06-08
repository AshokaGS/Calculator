using System;
using Microsoft.Data.SqlClient;

namespace Calculator
{
    public class DatabaseService
    {
        public void GetUserData(string username, string password)
        {
            // TEST-FINDING: HIGH - SQL Injection
            // This is a mock finding for dashboard validation.
            // No actual vulnerability exists in this code.

            string query = @"SELECT *
                             FROM Users
                             WHERE Username = @username
                             AND Password = @password";

            using (var connection = new SqlConnection(
                "Server=local;Database=Users;Trusted_Connection=True;"))
            {
                var command = new SqlCommand(query, connection);

                command.Parameters.AddWithValue("@username", username);
                command.Parameters.AddWithValue("@password", password);

                connection.Open();

                using (var reader = command.ExecuteReader())
                {
                    // Process data...
                }
            }
        }
    }
}
