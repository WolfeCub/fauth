import axios from "axios";
import { createResource, For } from "solid-js";

export const Admin = () => {
    const [users] = createResource(async () =>
        await axios.get<{ users: string[] }>("http://some.domain:8888/api/admin/users", {
            withCredentials: true,
        })
    );

    return (
        <>
            <table class="table-auto">
                <thead>
                    <tr>
                        <th>User</th>
                    </tr>
                </thead>
                <tbody>
                    <For each={users()?.data.users}>{(user, i) =>
                        <tr>
                            <td>{user}</td>
                        </tr>
                    }</For>
                </tbody>
            </table>
        </>
    );
};
