import Head from "next/head";
import { useAuth } from "./_app";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

function ProfileSection({
  title,
  details,
}: {
  title: string;
  details: { label: string; value: string }[];
}) {
  return (
    <section className="panel profile-section">
      <h2>{title}</h2>
      <dl className="profile-details">
        {details.map((detail) => (
          <div className="profile-detail" key={detail.label}>
            <dt>{detail.label}</dt>
            <dd>{detail.value || "Not provided"}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

export default function Profile() {
  const { user } = useAuth();
  if (!user) return null;

  const accountType =
    user.account_type === "student" ? "Student" : "Working professional";
  const accountDetails =
    user.account_type === "student"
      ? [
          { label: "School, college, or university", value: user.institution },
          { label: "School year or session", value: user.academic_session },
          { label: "Department or field of study", value: user.department },
          { label: "Course or program", value: user.course },
          { label: "Current year of study", value: user.study_year },
        ]
      : [
          { label: "Company or employer", value: user.employer },
          { label: "Department or team", value: user.department },
          { label: "Job title", value: user.job_title },
          { label: "Work arrangement", value: user.employment_type },
          { label: "Employee or staff ID", value: user.employee_id },
        ];
  const createdAt = user.created_at
    ? new Date(user.created_at).toLocaleDateString()
    : "Not available";

  return (
    <>
      <Head>
        <title>My profile · UPI Shield</title>
      </Head>
      <div className="profile-page">
        <header className="page-header">
          <div>
            <div className="eyebrow">YOUR DETAILS</div>
            <h1>My profile</h1>
            <p>View the personal and {accountType.toLowerCase()} details saved to your account.</p>
          </div>
          <span className="profile-type-badge">{accountType}</span>
        </header>

        <div className="profile-grid">
          <ProfileSection
            title="About you"
            details={[
              { label: "Full name", value: user.full_name },
              { label: "Email address", value: user.email },
              { label: "Mobile number", value: user.mobile_number },
              { label: "Email address status", value: user.is_verified ? "Confirmed" : "Not confirmed" },
              { label: "Account created", value: createdAt },
            ]}
          />
          <ProfileSection title={`${accountType} details`} details={accountDetails} />
        </div>

        {user.account_type === "student" && (
          <section className="panel profile-document">
            <div>
              <h2>Your student ID card</h2>
              <p>
                This file is private. You must be signed in to view it.
              </p>
            </div>
            {user.has_student_id_document ? (
              <a
                className="button primary"
                href={`${API}/auth/profile/student-id-card`}
              >
                View or download ID card
              </a>
            ) : (
              <span className="profile-muted">No ID card has been added.</span>
            )}
          </section>
        )}
      </div>
    </>
  );
}
